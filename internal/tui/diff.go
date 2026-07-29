package tui

import (
	"github.com/SuperMarioYL/forkspan/internal/ingest"
)

// DiffView is the side-by-side recorded-vs-counterfactual subgraph view. It
// is the m2 milestone and is NOT rendered in m1 — the navigator's 'd' key
// surfaces a roadmap pointer instead.
//
// TODO(m2_fork_diff): build the recorded subgraph (diff.Subgraph) and the
// counterfactual projection (fork.Project), align by span id, classify each
// divergence (added/removed/mutated), and render two columns with divergence
// highlights + NeedsReExec flags. See mvp_plan.md §5 m2; consumed by the 'd'
// key in tree.go.
type DiffView struct {
	Recorded     []ingest.Span
	Counterfactual []ingest.Span
	// Divergences []diff.Divergence
}

// Render is the m2 renderer for the DiffView. Empty in m1.
func (DiffView) Render() string { return "" }
