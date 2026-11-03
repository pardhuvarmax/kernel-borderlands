package controlplane

import (
	"sync"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// Process-tree evidence (feature schema v4, plan item B2/B5).
//
// The attack-lab corpora show the file read and the network connect of one
// attack are usually done by DIFFERENT processes (for example a python
// process runs `sudo cat /etc/shadow` as a child and then makes the connect
// itself), so a per-process score never holds both. treeCache keeps, per
// process, the highest file and network dimension scores it has ever shown
// and aggregates them up the tree: a process's tree_* values are the maximum
// over its own subtree (itself and all descendants kbd has seen).
//
// Rules, each of which fixed a real defect found by replaying the lab
// corpora (scripts/attack-lab/build_training_table.py):
//   - Evidence only goes up. The sensor's dimension scores are the score of
//     the LAST event, and the final process_state a process sends as it exits
//     has them zeroed, so "latest value" erased a short-lived reader's
//     evidence exactly when it exited.
//   - A ppid of 0 means "unknown" (that same exit snapshot), not "re-parented":
//     the previous parent is kept. Treating it as re-parenting detached the
//     reader from its parent.
//   - Descendants feed ancestors, not siblings. An earlier parent-plus-siblings
//     scope caught 16 of 110 attack executions; the subtree catches the
//     intended families.
//
// Other choices:
//   - The walk is bounded (treeMaxDepth levels, treeMaxVisit nodes) so a
//     process with thousands of descendants costs O(1) per update; beyond the
//     bound the value is a lower bound.
//   - PIDs are host-namespace tgids (kbd_sensor.bpf.c uses
//     bpf_get_current_pid_tgid and real_parent->tgid), so a container's init
//     is NOT pid 1 here and is treated like any other parent.
//   - An exited process keeps contributing for treeExitedTTL, a running one
//     for treeStaleTTL since its last update.
//   - PID reuse is guarded by StartTimeNs.
//   - Known hazard: a long-lived parent whose descendants collectively read
//     sensitive files and connect (a supervisor, sshd, cron, or the attack-lab
//     runner itself) will look like "both" indefinitely. In the lab corpora one
//     such process produced most flagged background rows. This is a feature,
//     not a verdict: nothing enforces on it.
//   - Memory is bounded by treeMaxNodes; this is a cache, not persisted.
const (
	treeExitedTTL = 120 * time.Second
	treeStaleTTL  = 10 * time.Minute
	treeMaxNodes  = 65536
	// treeMaxVisit and treeMaxDepth bound the descendant walk per update.
	treeMaxVisit = 256
	treeMaxDepth = 6
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

// Update records a process's scores and returns its subtree aggregates: the
// highest file and network dimension scores across the process and its
// descendants, and the lower of the two (high only when BOTH kinds of
// evidence exist somewhere in the subtree).
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
	ppid := msg.PPID
	n, ok := t.nodes[msg.PID]
	if ok && n.start != msg.StartTimeNs && n.start != 0 && msg.StartTimeNs != 0 {
		t.drop(msg.PID) // PID reused by a different process
		ok = false
	}
	if ok && ppid == 0 {
		ppid = n.ppid // 0 = unknown (exit snapshot), keep the parent
	}
	if !ok {
		n = &treeNode{}
		t.nodes[msg.PID] = n
	} else if n.ppid != ppid {
		t.unlink(msg.PID, n)
	}
	n.ppid, n.start = ppid, msg.StartTimeNs
	n.file = maxf(n.file, msg.DimScore[dimFileIdx]) // evidence only goes up
	n.net = maxf(n.net, msg.DimScore[dimNetworkIdx])
	n.seen, n.exitedAt = now, time.Time{}
	if ppid > 1 {
		c := t.children[ppid]
		if c == nil {
			c = map[uint32]struct{}{}
			t.children[ppid] = c
		}
		c[msg.PID] = struct{}{}
	}
	return t.aggregate(msg.PID, now)
}

func (t *treeCache) aggregate(root uint32, now time.Time) (file, net, both float64) {
	type item struct {
		pid   uint32
		depth int
	}
	stack := []item{{root, 0}}
	visited := 0
	for len(stack) > 0 && visited < treeMaxVisit {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visited++
		if m, ok := t.nodes[it.pid]; ok && t.live(m, now) {
			file, net = maxf(file, m.file), maxf(net, m.net)
		}
		if it.depth < treeMaxDepth {
			for c := range t.children[it.pid] {
				stack = append(stack, item{c, it.depth + 1})
			}
		}
	}
	return file, net, minf(file, net)
}

// live reports whether a node still contributes: an exited process for
// treeExitedTTL after its exit, a running one for treeStaleTTL after its last
// update.
func (t *treeCache) live(m *treeNode, now time.Time) bool {
	if !m.exitedAt.IsZero() {
		return now.Sub(m.exitedAt) <= treeExitedTTL
	}
	return now.Sub(m.seen) <= treeStaleTTL
}

// Exit marks a process as gone; its scores keep counting for treeExitedTTL.
func (t *treeCache) Exit(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[pid]; ok {
		n.exitedAt = t.now()
	}
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
