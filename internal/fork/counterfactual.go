package fork

import (
	"errors"
	"fmt"

	"github.com/SuperMarioYL/forkspan/internal/ingest"
)

// Branch is a counterfactual branch off a StateSnapshot: the parent
// snapshot, the mutation applied at the fork point, the projected downstream
// tool-call subgraph, and the divergences it produced.
//
// TODO(m2_fork_diff): Branch is the m2 milestone — Snapshot() (m1) only
// captures the root state; Project() walks the recorded span tree applying
// the mutation and structurally projecting the downstream tool-call
// subgraph. Live LLM re-execution is explicitly out of scope for v0.1;
// uncertain divergences are surfaced via Divergence.NeedsReExec instead of
// being silently claimed. See mvp_plan.md §5 m2 milestone.
type Branch struct {
	Parent            StateSnapshot
	Mutation          Mutation
	ProjectedSubgraph []ingest.Span
	Divergences       []DivergenceRef
}

// DivergenceRef is a forward reference to diff.Divergence; declared here so
// the Branch type is self-contained without an import cycle. diff.Divergence
// is the concrete type.
type DivergenceRef = struct {
	SpanID              string
	RecordedToolCall    string
	ProjectedToolCall   string
	Kind                int // added | removed | mutated
	NeedsReExec         bool
}

// ErrNotImplemented is returned by every m2 entry point until the milestone
// lands. The CLI prints a friendly pointer to the roadmap instead of leaking
// this error to the operator.
var ErrNotImplemented = errors.New("forkspan: counterfactual projection lands in the m2 milestone (see roadmap)")

// Project applies a mutation to a StateSnapshot and projects the downstream
// tool-call subgraph. NOT IMPLEMENTED in m1.
//
// TODO(m2_fork_diff): project block_tool / redact_payload / harden_policy
// over the recorded span tree, emit the projected subgraph + divergences,
// and set NeedsReExec wherever structural projection is uncertain. See
// mvp_plan.md §5 m2.
func Project(_ StateSnapshot, _ Mutation) (Branch, error) {
	return Branch{}, fmt.Errorf("%w: Project()", ErrNotImplemented)
}

// Branches enumerates the counterfactual branches off a snapshot given a set
// of candidate mutations. NOT IMPLEMENTED in m1.
//
// TODO(m2_fork_diff): see mvp_plan.md §5 m2.
func Branches(_ StateSnapshot, _ []Mutation) ([]Branch, error) {
	return nil, fmt.Errorf("%w: Branches()", ErrNotImplemented)
}
