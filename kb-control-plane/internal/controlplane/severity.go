package controlplane

import (
	"path/filepath"
	"strings"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// severityTiers, ordered low -> high, per CWP.md §9.2's example
// ("Medium -> High, High -> Critical"). classifySeverity buckets a raw
// 0-100 score into one of these; escalateSeverity bumps exactly one tier,
// capped at CRITICAL.
var severityTiers = []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}

// classifySeverity buckets a raw composite/EMA score (0-100) into a base
// severity tier. Thresholds are deliberately conservative around the
// existing SUSPICIOUS(40)/BORDERLANDS(75) defaults in config/policy.yaml
// so a BORDERLANDS-zone entry (score >= ~75 in practice) lands at HIGH or
// CRITICAL under normal operation — consistent with every alert observed
// pre-this-change always being "CRITICAL".
func classifySeverity(score float64) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 75:
		return "HIGH"
	case score >= 50:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// escalateSeverity bumps sev exactly one tier per CWP.md §9.2, capped at
// CRITICAL (there is no tier above it to escalate into). An unrecognized
// input is treated as the lowest tier rather than erroring, since this
// only ever feeds a display/routing field, never a security decision.
func escalateSeverity(sev string) string {
	for i, t := range severityTiers {
		if t == sev {
			if i == len(severityTiers)-1 {
				return sev
			}
			return severityTiers[i+1]
		}
	}
	return severityTiers[1] // unknown input: treat conservatively as one above LOW
}

// cwpMatch is what findCWPMatch returns on a hit — enough to populate an
// Alert's protected_workload/owner_team/justification/policy_id fields
// (CWP.md §9.3's example alert) and to log/audit a CWP-specific event.
type cwpMatch struct {
	PolicyID      uint32
	OwnerTeam     string
	Justification string
	Path          string
}

// findCWPMatch checks whether comm (the process's short name, as carried
// by ProcessState/ZoneTransition's wire comm[16] field) matches a
// CWP-registered workload's executable basename.
//
// IMPORTANT LIMITATION, stated plainly: this is a basename match, not the
// canonical-resolved-path match CWP.md §5.2/§11.2 requires for actual
// containment-exemption decisions — kbd never receives a process's full
// resolved path over the wire today (only comm, a 16-byte process name).
// The real, path-resolved, spoofing-resistant match already happens
// kernel-side in kb-core's cwp_classify() for the actual "should this be
// contained" decision (CWP.md §7-§8) — that enforcement path is
// unaffected by this function. This lookup exists ONLY to decide whether
// an already-generated alert should carry CWP's severity escalation and
// metadata (CWP.md §9), a lower-stakes, display/routing-only purpose
// where a basename-level match (with the same process-name-spoofing
// caveat §11.2 already documents for comm generally) is an acceptable,
// honestly-caveated trade-off rather than silently pretending full-path
// fidelity Go doesn't have visibility into.
func findCWPMatch(registry []ipc.CWPWorkloadEntry, comm string) (cwpMatch, bool) {
	if comm == "" {
		return cwpMatch{}, false
	}
	for _, e := range registry {
		if filepath.Base(e.Path) == comm || strings.EqualFold(filepath.Base(e.Path), comm) {
			return cwpMatch{
				PolicyID:      e.PolicyID,
				OwnerTeam:     e.OwnerTeam,
				Justification: e.Justification,
				Path:          e.Path,
			}, true
		}
	}
	return cwpMatch{}, false
}

// cwpRegistrySnapshot returns a read-locked copy of the currently loaded
// CWP registry for lookup purposes (findCWPMatch never mutates it, so a
// shared slice reference is safe — entries are only ever replaced
// wholesale by reloadWorkloadsFromDisk, never mutated in place).
func (cp *ControlPlane) cwpRegistrySnapshot() []ipc.CWPWorkloadEntry {
	cp.cwpRegistryMu.RLock()
	defer cp.cwpRegistryMu.RUnlock()
	return cp.cwpRegistry
}
