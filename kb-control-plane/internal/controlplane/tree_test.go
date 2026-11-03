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

// The case per-process scores cannot see: a reader and a connector are
// different processes under one parent.
func TestTree_SiblingsShareEvidence(t *testing.T) {
	c := newTreeCache()
	c.Update(st(100, 1000, 1, 0, 0)) // parent
	if f, n, b := c.Update(st(101, 100, 2, 80, 0)); f != 80 || n != 0 || b != 0 {
		t.Fatalf("reader alone: f=%v n=%v both=%v", f, n, b)
	}
	f, n, b := c.Update(st(102, 100, 3, 0, 70)) // connector sibling
	if f != 80 || n != 70 || b != 70 {
		t.Fatalf("connector should see the reader: f=%v n=%v both=%v", f, n, b)
	}
	// the reader's next sample now sees the connector too
	if f, n, b := c.Update(st(101, 100, 2, 80, 0)); f != 80 || n != 70 || b != 70 {
		t.Fatalf("reader should see the connector: f=%v n=%v both=%v", f, n, b)
	}
}

func TestTree_UnrelatedProcessesDoNotMix(t *testing.T) {
	c := newTreeCache()
	c.Update(st(101, 100, 2, 80, 0))
	if _, n, b := c.Update(st(202, 200, 3, 0, 90)); n != 90 || b != 0 {
		t.Fatalf("different parents must not share: n=%v both=%v", n, b)
	}
	// parent pid 0/1 or unknown: family is the process itself
	c.Update(st(301, 1, 4, 80, 0))
	if _, _, b := c.Update(st(302, 1, 5, 0, 90)); b != 0 {
		t.Fatalf("children of init must not be grouped, both=%v", b)
	}
}

func TestTree_ExitedReaderCountsUntilTTL(t *testing.T) {
	c := newTreeCache()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Update(st(101, 100, 2, 80, 0))
	c.Exit(101)
	now = now.Add(30 * time.Second)
	if _, _, b := c.Update(st(102, 100, 3, 0, 70)); b != 70 {
		t.Fatalf("recently exited reader should still count, both=%v", b)
	}
	now = now.Add(treeExitedTTL + time.Second)
	if _, _, b := c.Update(st(102, 100, 3, 0, 70)); b != 0 {
		t.Fatalf("expired reader must not count, both=%v", b)
	}
}

func TestTree_PidReuseDoesNotInherit(t *testing.T) {
	c := newTreeCache()
	c.Update(st(101, 100, 2, 80, 0))
	// same pid, different start time, different parent: a new process
	if f, _, _ := c.Update(st(101, 500, 99, 0, 0)); f != 0 {
		t.Fatalf("reused pid inherited old evidence: f=%v", f)
	}
	if f, _, _ := c.Update(st(103, 100, 4, 0, 0)); f != 0 {
		t.Fatalf("old family still lists reused pid: f=%v", f)
	}
}

func TestTree_BoundedAndFailsSafe(t *testing.T) {
	c := newTreeCache()
	for i := uint32(0); i < treeMaxNodes; i++ {
		c.Update(st(10+i, 5, uint64(i)+1, 0, 0))
	}
	if len(c.nodes) > treeMaxNodes {
		t.Fatalf("cache grew past its bound: %d", len(c.nodes))
	}
	f, n, b := c.Update(st(900000, 5, 1, 40, 30)) // full, nothing expired
	if f != 40 || n != 30 || b != 30 || len(c.nodes) > treeMaxNodes {
		t.Fatalf("full cache must fall back to the process's own scores: %v %v %v nodes=%d", f, n, b, len(c.nodes))
	}
}
