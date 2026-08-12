package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleTraceRel is the bundled compromised-agent fixture, resolved relative
// to the cmd/forkspan package dir (the test process's cwd).
const sampleTraceRel = "../../testdata/sample-compromised-trace.json"

// sampleTraceAbs resolves the fixture to an absolute path so the inspect
// command keeps working after the default-path test chdir's into a temp dir.
func sampleTraceAbs(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(sampleTraceRel)
	if err != nil {
		t.Fatalf("resolve %s: %v", sampleTraceRel, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("sample trace not found at %s: %v", abs, err)
	}
	return abs
}

// TestSnapshotOutPath_ExplicitOutWinsOverJSON is the regression test for
// fix-inspect-snapshot-stdout-out-collision (resolution half): an explicit
// --out must win even under --json, so `inspect -s <id> --json -o <path>`
// resolves the destination to that path (and DumpSnapshot then writes the
// file). Pre-fix snapshotOutPath returned "-" whenever asJSON was true —
// regardless of --out — so DumpSnapshot took the `path == "-"` early-return and
// never wrote the file; this test fails on that code.
func TestSnapshotOutPath_ExplicitOutWinsOverJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "snap.json")
	got := snapshotOutPath(true, out)
	if got != out {
		t.Errorf("snapshotOutPath(true, %q) = %q, want %q (explicit --out must win over --json)", out, got, out)
	}
}

// TestSnapshotOutPath_Defaults pins the non-regressed branches of the
// resolution table so the contract stays documented alongside the regression.
func TestSnapshotOutPath_Defaults(t *testing.T) {
	if got := snapshotOutPath(false, ""); got != "forkspan-snapshot.json" {
		t.Errorf("snapshotOutPath(false, \"\") = %q, want forkspan-snapshot.json", got)
	}
	if got := snapshotOutPath(true, ""); got != "-" {
		t.Errorf("snapshotOutPath(true, \"\") = %q, want -", got)
	}
	if got := snapshotOutPath(false, "/tmp/explicit.json"); got != "/tmp/explicit.json" {
		t.Errorf("snapshotOutPath(false, \"/tmp/explicit.json\") = %q, want /tmp/explicit.json", got)
	}
}

// TestInspectSnapshot_JSONOutWritesFile is the regression test for
// fix-inspect-snapshot-stdout-out-collision (print half, explicit --out): the
// non-interactive `inspect -s <id> --json -o <path>` must write the snapshot
// file at <path> (and echo the JSON to stdout). Pre-fix the resolved path
// collapsed to "-" and DumpSnapshot early-returned without calling
// os.WriteFile, silently dropping --out; this test fails on that code.
func TestInspectSnapshot_JSONOutWritesFile(t *testing.T) {
	trace := sampleTraceAbs(t)
	out := filepath.Join(t.TempDir(), "snap.json")

	var stdout bytes.Buffer
	root := newRoot()
	root.SetArgs([]string{"inspect", trace, "-s", "0a0b0c0d0e0f0a0b", "--json", "-o", out})
	root.SetOut(&stdout)
	if err := root.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("snapshot file not written at %s: %v (regression: --json -o <path> silently dropped --out)", out, err)
	}
	if info.Size() == 0 {
		t.Fatalf("snapshot file %s is empty", out)
	}
	if !strings.Contains(stdout.String(), "at_span_id") {
		t.Errorf("stdout = %q, want JSON containing at_span_id (the --json echo)", stdout.String())
	}
}

// TestInspectSnapshot_DefaultPathNoDoubleOutput is the regression test for
// fix-inspect-snapshot-stdout-out-collision (print half, default path): with
// neither --json nor --out the snapshot is written to the default file and
// stdout must carry only the "snapshot written → ..." summary — NOT the full
// JSON. Pre-fix the print condition was `asJSON || outPath == ""`, so the
// default path (outPath == "") double-output the JSON to stdout AND wrote the
// file; this test fails on that code. Post-fix the print branch drives on
// asJSON alone, so the default path writes the file once and prints the
// summary.
func TestInspectSnapshot_DefaultPathNoDoubleOutput(t *testing.T) {
	trace := sampleTraceAbs(t)
	dir := t.TempDir()
	// The default path writes "forkspan-snapshot.json" to cwd, so run from a
	// temp dir to avoid polluting the repo and to assert the file lands there.
	t.Chdir(dir)

	var stdout bytes.Buffer
	root := newRoot()
	root.SetArgs([]string{"inspect", trace, "-s", "0a0b0c0d0e0f0a0b"})
	root.SetOut(&stdout)
	if err := root.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "forkspan-snapshot.json")); err != nil {
		t.Fatalf("default snapshot file not written to temp dir: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "snapshot written") {
		t.Errorf("stdout = %q, want the \"snapshot written → ...\" summary line", got)
	}
	if strings.Contains(got, "at_span_id") {
		t.Errorf("stdout must not echo the snapshot JSON on the default path (double output): got %q", got)
	}
}
