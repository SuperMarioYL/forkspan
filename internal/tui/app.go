// Package tui is ForkSpan's bubbletea navigator for the recorded span tree.
//
// The m1 milestone renders the span tree + tool-call subgraph, lets the
// operator navigate, mark the intrusion span, and dump the StateSnapshot.
// The side-by-side recorded-vs-counterfactual diff view is the m2 milestone
// (see diff.go).
package tui

import (
	"fmt"
	"os"

	"github.com/SuperMarioYL/forkspan/internal/diff"
	"github.com/SuperMarioYL/forkspan/internal/fork"
	"github.com/SuperMarioYL/forkspan/internal/ingest"
	tea "github.com/charmbracelet/bubbletea"
)

// Run opens the bubbletea navigator over tree. The pre-marked intrusion span
// (if the sample trace set one) is highlighted up front.
func Run(tree *ingest.Tree) error {
	preMark := tree.IntrusionSpan()
	m := newModel(tree, preMark)
	if _, err := runProgram(m); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

// DumpSnapshot writes the StateSnapshot at atSpanID to path as JSON. Used by
// the non-interactive `inspect --snapshot <id> --json` path so the m1
// milestone can dump the snapshot to stdout without a TUI.
func DumpSnapshot(tree *ingest.Tree, atSpanID, path string) ([]byte, error) {
	snap, err := fork.Snapshot(tree, atSpanID)
	if err != nil {
		return nil, err
	}
	b, err := snap.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if path == "-" || path == "" {
		return b, nil
	}
	return b, os.WriteFile(path, b, 0o644)
}

// RenderSubgraph proxies diff.RenderSubgraph for the inspect command's
// non-interactive summary.
func RenderSubgraph(tree *ingest.Tree, fromSpanID string) string {
	return diff.RenderSubgraph(diff.Subgraph(tree, fromSpanID))
}

// runProgram launches the bubbletea program for the navigator model.
func runProgram(m *model) (*model, error) {
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	if fm, ok := final.(*model); ok {
		return fm, nil
	}
	return m, nil
}

// writeFile is a thin wrapper so the TUI can flush the snapshot without
// pulling os into the model file's hot path.
func writeFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644)
}
