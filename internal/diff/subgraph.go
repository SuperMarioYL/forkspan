// Package diff renders the tool-call subgraph and (in m2) the recorded vs.
// counterfactual divergence. The m1 milestone implements the subgraph
// extraction that the `inspect` navigator displays; the side-by-side
// recorded-vs-counterfactual diff is the m2 milestone (see Diff).
package diff

import (
	"errors"
	"fmt"
	"sort"

	"github.com/SuperMarioYL/forkspan/internal/ingest"
)

// DivKind classifies a divergence between a recorded tool-call and its
// counterfactual projection.
type DivKind int

const (
	DivAdded DivKind = iota + 1
	DivRemoved
	DivMutated
)

// String renders a DivKind for display.
func (k DivKind) String() string {
	switch k {
	case DivAdded:
		return "added"
	case DivRemoved:
		return "removed"
	case DivMutated:
		return "mutated"
	}
	return "unknown"
}

// Divergence is a single recorded-vs-projected difference. NeedsReExec is the
// honesty seam: where structural projection (m2) is uncertain, ForkSpan flags
// it rather than claiming counterfactual execution it does not perform.
type Divergence struct {
	SpanID            string
	RecordedToolCall  string
	ProjectedToolCall string
	Kind              DivKind
	NeedsReExec       bool
}

// Subgraph extracts the downstream tool-call subgraph rooted at fromSpanID:
// every Role==Tool span reachable from fromSpanID's descendants, in start
// order. This is the slice the m1 navigator renders and the slice a
// counterfactual (m2) projects + diffs against.
func Subgraph(tree *ingest.Tree, fromSpanID string) []ingest.Span {
	if tree == nil || tree.Get(fromSpanID) == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []ingest.Span
	var walk func(id string)
	walk = func(id string) {
		for _, cid := range tree.Children(id) {
			if seen[cid] {
				continue
			}
			seen[cid] = true
			c := tree.Get(cid)
			if c == nil {
				continue
			}
			if c.IsToolCall() {
				out = append(out, *c)
			}
			walk(cid)
		}
	}
	walk(fromSpanID)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// RenderSubgraph formats a tool-call subgraph as one line per span, used by
// the non-interactive `inspect` output and the demo.
func RenderSubgraph(spans []ingest.Span) string {
	if len(spans) == 0 {
		return "(no downstream tool calls)"
	}
	var b []byte
	for _, s := range spans {
		tool := s.ToolName
		if tool == "" {
			tool = s.Name
		}
		line := fmt.Sprintf("  %s  %s  status=%s  dur=%s\n", s.SpanID, tool, s.Status, s.Duration())
		b = append(b, []byte(line)...)
	}
	return string(b)
}

// ErrDiffNotImplemented guards the m2 diff entry points.
var ErrDiffNotImplemented = errors.New("forkspan: recorded-vs-counterfactual diff lands in the m2 milestone (see roadmap)")

// Diff computes the recorded-vs-projected divergence list for a
// counterfactual branch. NOT IMPLEMENTED in m1.
//
// TODO(m2_fork_diff): align the recorded tool-call subgraph with the
// projected subgraph by span id, classify each as added/removed/mutated,
// and set NeedsReExec wherever the projection is uncertain (e.g. a payload
// redaction that could change an LLM's downstream choice). See mvp_plan.md
// §5 m2.
func Diff(_ []ingest.Span, _ []ingest.Span) ([]Divergence, error) {
	return nil, fmt.Errorf("%w: Diff()", ErrDiffNotImplemented)
}

// RenderSideBySide formats the recorded and counterfactual subgraphs in two
// columns for the TUI diff view. NOT IMPLEMENTED in m1.
//
// TODO(m2_fork_diff): see mvp_plan.md §5 m2; consumed by internal/tui/diff.go.
func RenderSideBySide(_ []ingest.Span, _ []ingest.Span, _ []Divergence) string {
	return ""
}
