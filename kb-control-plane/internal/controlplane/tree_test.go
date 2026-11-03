package controlplane

import (
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

func st(pid, ppid uint32, start uint64, file, net float64) *ipc.ProcessStateMsg {
	m := &ipc.ProcessStateMsg{PID: pid, PPID: ppid, StartTimeNs: start}
	m.DimScore[dimFileIdx], m.DimScore[dimNetworkIdx] = file, net
	return m
}

// The case per-process scores cannot see, taken from the lab corpora: a
// python process runs `sudo cat /etc/shadow` (a grandchild reads) and then
// makes the connect itself. Descendants feed ancestors.
func TestTree_AncestorSeesDescendantEvidence(t *testing.T) {
	c := newTreeCache()
	c.Update(st(201, 200, 2, 80, 0))             // sudo's child cat: file evidence
	c.Update(st(200, 100, 1, 0, 0))              // sudo
	f, n, b := c.Update(st(100, 1000, 0, 0, 15)) // python: the connect
	if f != 80 || n != 15 || b != 15 {
		t.Fatalf("python should see its grandchild's file evidence: f=%v n=%v both=%v", f, n, b)
	}
	// the reader itself does not see the connect made by its ancestor
	if _, n, b := c.Update(st(201, 200, 2, 80, 0)); n != 0 || b != 0 {
		t.Fatalf("a descendant must not inherit an ancestor's evidence: n=%v both=%v", n, b)
	}
}

// Defect found in the lab corpora: the last process_state a process sends has
// ppid 0 and zeroed dimensions. It must neither detach the process from its
// parent nor erase its evidence.
func TestTree_ExitSnapshotKeepsParentAndEvidence(t *testing.T) {
	c := newTreeCache()
	c.Update(st(101, 100, 2, 80, 0))
	c.Update(st(101, 0, 2, 0, 0)) // exit snapshot
	if f, _, _ := c.Update(st(100, 1000, 1, 0, 15)); f != 80 {
		t.Fatalf("exit snapshot erased the reader's evidence or parent link: f=%v", f)
	}
}

func TestTree_SiblingsAndInitChildrenDoNotMix(t *testing.T) {
	c := newTreeCache()
	c.Update(st(101, 100, 2, 80, 0))
	if _, n, b := c.Update(st(102, 100, 3, 0, 15)); n != 15 || b != 0 {
		t.Fatalf("a sibling's evidence must not leak sideways: n=%v both=%v", n, b)
	}
	c.Update(st(301, 1, 4, 80, 0))
	if _, _, b := c.Update(st(302, 1, 5, 0, 15)); b != 0 {
		t.Fatalf("children of init are not a family, both=%v", b)
	}
	if _, _, b := c.Update(st(200, 999, 6, 0, 15)); b != 0 { // unrelated parent
		t.Fatalf("unrelated parent saw evidence, both=%v", b)
	}
}

func TestTree_ExitedReaderCountsUntilTTL(t *testing.T) {
	c := newTreeCache()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Update(st(101, 100, 2, 80, 0))
	c.Exit(101)
	now = now.Add(30 * time.Second)
	if _, _, b := c.Update(st(100, 1000, 1, 0, 15)); b != 15 {
		t.Fatalf("recently exited reader should still count, both=%v", b)
	}
	now = now.Add(treeExitedTTL + time.Second)
	if _, _, b := c.Update(st(100, 1000, 1, 0, 15)); b != 0 {
		t.Fatalf("expired reader must not count, both=%v", b)
	}
}

func TestTree_PidReuseDoesNotInherit(t *testing.T) {
	c := newTreeCache()
	c.Update(st(101, 100, 2, 80, 0))
	if f, _, _ := c.Update(st(101, 500, 99, 0, 0)); f != 0 { // same pid, new start time
		t.Fatalf("reused pid inherited old evidence: f=%v", f)
	}
	if f, _, _ := c.Update(st(100, 1000, 1, 0, 0)); f != 0 {
		t.Fatalf("old parent still lists the reused pid: f=%v", f)
	}
}

func TestTree_BoundedAndFailsSafe(t *testing.T) {
	c := newTreeCache()
	for i := uint32(0); i < treeMaxNodes; i++ {
		c.Update(st(10+i, 5, uint64(i)+1, 0, 0)) // one parent with 65k children
	}
	start := time.Now()
	c.Update(st(5, 4, 1, 0, 15)) // the parent: walk is bounded
	if time.Since(start) > time.Second || len(c.nodes) > treeMaxNodes+1 {
		t.Fatalf("walk or cache not bounded: %v, %d nodes", time.Since(start), len(c.nodes))
	}
	f, n, b := c.Update(st(900000, 5, 1, 40, 30)) // cache full, nothing expired
	if f != 40 || n != 30 || b != 30 || len(c.nodes) > treeMaxNodes+1 {
		t.Fatalf("full cache must fall back to the process's own scores: %v %v %v nodes=%d", f, n, b, len(c.nodes))
	}
}
