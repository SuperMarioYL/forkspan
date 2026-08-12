// Command forkspan is the entry point for the ForkSpan fork primitive.
//
// m1 surface: `forkspan inspect <trace.json>` loads an OTel-GenAI span
// export, renders the recorded span tree in a bubbletea navigator, lets the
// operator mark the intrusion span, and dumps the StateSnapshot.
//
// `forkspan fork` and `forkspan replay` are the m2/m3 milestones and print a
// roadmap pointer (see mvp_plan.md §5).
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/SuperMarioYL/forkspan/internal/fork"
	"github.com/SuperMarioYL/forkspan/internal/ingest"
	"github.com/SuperMarioYL/forkspan/internal/tui"
	"github.com/spf13/cobra"
)

var version = "v0.3.0"

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "forkspan:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "forkspan",
		Short: "Fork an agent run compromised mid-run — replay counterfactuals over OTel-GenAI spans",
		Long: `ForkSpan is a first-class fork primitive for agent runs compromised mid-run.

It snapshots the recorded state at the intrusion span (over OTel-GenAI spans)
so an operator can inspect + counterfactually replay from a fork point without
killing the run and losing the causal chain.

The m1 milestone loads a recorded OTLP-GenAI JSON export, renders the span tree,
and dumps the StateSnapshot at any span. Counterfactual projection + diff land
in the m2 milestone; live re-execution is post-v0.1.`,
		Version: version,
	}
	root.AddCommand(newInspectCmd(), newForkCmd(), newReplayCmd())
	return root
}

// newInspectCmd implements the m1 navigator.
func newInspectCmd() *cobra.Command {
	var (
		snapshotID string
		asJSON     bool
		outPath    string
	)
	c := &cobra.Command{
		Use:   "inspect <trace.json>",
		Short: "Load a recorded OTel-GenAI trace, navigate the span tree, dump a StateSnapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tree, err := ingest.LoadFile(args[0])
			if err != nil {
				return err
			}
			if len(tree.Spans) == 0 {
				return fmt.Errorf("no spans in %s", args[0])
			}

			// Non-interactive snapshot dump path (the m1 "dump to stdout").
			if snapshotID != "" {
				// Resolve the destination once and drive the print branch on
				// --json alone: an explicit --out is honored under --json
				// (file + stdout), and the default-path case no longer echoes
				// the full JSON to stdout AND writes the file.
				resolved := snapshotOutPath(asJSON, outPath)
				b, err := tui.DumpSnapshot(tree, snapshotID, resolved)
				if err != nil {
					return err
				}
				if asJSON {
					fmt.Fprintln(cmd.OutOrStdout(), string(b))
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "snapshot written → %s\n", resolved)
				}
				return nil
			}

			// Interactive navigator.
			fmt.Fprintf(cmd.ErrOrStderr(), "loaded %d spans from %s — opening navigator (forkspan.intrusion pre-mark: %s)\n",
				len(tree.Spans), args[0], markLabel(tree.IntrusionSpan()))
			return tui.Run(tree)
		},
	}
	c.Flags().StringVarP(&snapshotID, "snapshot", "s", "", "dump the StateSnapshot at this span id (non-interactive)")
	c.Flags().BoolVar(&asJSON, "json", false, "emit the snapshot as JSON to stdout (with --snapshot)")
	c.Flags().StringVarP(&outPath, "out", "o", "", "write the snapshot to this path (default: forkspan-snapshot.json)")
	return c
}

// snapshotOutPath resolves where DumpSnapshot should write the snapshot JSON.
// An explicit --out always wins (so `--json -o <path>` writes the file AND
// echoes JSON to stdout). Without --out: --json dumps to stdout only ("-",
// no file); the plain default writes forkspan-snapshot.json.
func snapshotOutPath(asJSON bool, out string) string {
	if out != "" {
		return out
	}
	if asJSON {
		return "-" // stdout, no file
	}
	return "forkspan-snapshot.json"
}

// newForkCmd is the m2 milestone entry point. In v0.1 it prints a roadmap
// pointer rather than faking counterfactual projection. It still registers
// the documented m2 flags (--span / --block-tool, see README.md §Usage and
// docs/demo.tape) so the documented invocations parse and print the roadmap
// pointer instead of cobra exiting 1 on "unknown flag: --span".
func newForkCmd() *cobra.Command {
	var (
		spanID    string
		blockTool string
	)
	c := &cobra.Command{
		Use:   "fork",
		Short: "Snapshot the recorded state at a span and apply a counterfactual (m2 milestone)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), fork.ErrNotImplemented.Error())
			fmt.Fprintln(cmd.OutOrStdout(), "Track progress in the roadmap. The m1 `inspect` command already dumps the StateSnapshot.")
			return nil
		},
	}
	c.Flags().StringVar(&spanID, "span", "", "snapshot the StateSnapshot at this span id (m2 milestone)")
	c.Flags().StringVar(&blockTool, "block-tool", "", "block this tool-call in the counterfactual branch (m2 milestone)")
	return c
}

// newReplayCmd is the m2/m3 milestone entry point (counterfactual projection +
// side-by-side diff). In v0.1 it prints a roadmap pointer. It registers the
// documented m2/m3 flag (--branch, see README.md §Usage and docs/demo.tape)
// so the documented invocations parse and print the roadmap pointer instead
// of cobra exiting 1 on "unknown flag: --branch".
func newReplayCmd() *cobra.Command {
	var branch string
	c := &cobra.Command{
		Use:   "replay",
		Short: "Project a counterfactual branch and render the recorded-vs-projected diff (m2/m3)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), fork.ErrNotImplemented.Error())
			fmt.Fprintln(cmd.OutOrStdout(), "Replay is the m2 milestone; the recorded-vs-counterfactual diff view follows it.")
			return nil
		},
	}
	c.Flags().StringVar(&branch, "branch", "", "replay the counterfactual branch with this id (m2/m3)")
	return c
}

func markLabel(id string) string {
	if id == "" {
		return "none"
	}
	return id
}

// ensure encoding/json stays referenced when build tags change.
var _ = json.Marshal
