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

// ---- v0.5.0 milestones (fix-version-stale, fix-readme-snapshot-sample-stale,
// feat-inspect-list-tree) ----

// versionFileAbs resolves the repo-root VERSION file to an absolute path so the
// single-source-of-truth pin test keeps working regardless of any t.Chdir in
// an earlier test (testing restores cwd after each test, but be explicit).
func versionFileAbs(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../VERSION")
	if err != nil {
		t.Fatalf("resolve VERSION: %v", err)
	}
	return abs
}

// readmeAbs resolves a repo-root README to an absolute path (cmd/forkspan cwd).
func readmeAbs(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs("../../" + name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("%s not found at %s: %v", name, abs, err)
	}
	return abs
}

// TestVersion_VarIsTarget is the regression test for fix-version-stale: the
// in-source `version` package var must equal "v0.5.0" so a binary built at the
// v0.5.0 tag self-reports v0.5.0 (was stuck at "v0.3.0" through the v0.4.0
// release). Red on the current source (var is "v0.3.0"), green post-bump.
func TestVersion_VarIsTarget(t *testing.T) {
	if version != "v0.5.0" {
		t.Errorf("version var = %q, want %q (the v0.4.0 release shipped a binary self-reporting v0.3.0)", version, "v0.5.0")
	}
}

// TestVersion_FlagPrintsTarget is the regression test for fix-version-stale
// (flag half): `forkspan --version` must write a stdout line containing
// "v0.5.0". Red on the current source (cobra prints "... version v0.3.0"),
// green post-bump.
func TestVersion_FlagPrintsTarget(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.SetArgs([]string{"--version"})
	root.SetOut(&stdout)
	// cobra's --version handling calls os.Exit on success in some versions;
	// here Version is set so Execute returns nil and prints the version line.
	if err := root.Execute(); err != nil {
		// Some cobra versions short-circuit --version via SilenceUsage without
		// an error; only fail if there is a real error AND no version output.
		if stdout.Len() == 0 {
			t.Fatalf("--version: %v", err)
		}
	}
	if !strings.Contains(stdout.String(), "v0.5.0") {
		t.Errorf("--version stdout = %q, want a line containing v0.5.0", stdout.String())
	}
}

// TestVersion_VersionFileSingleSourceOfTruth is the guard pin for
// fix-version-stale: the in-source `version` var must equal the VERSION file's
// content so a future amend cannot bump one without the other. (Currently both
// are "v0.3.0", so this passes pre-bump and stays green post-bump — the point
// of a pin.)
func TestVersion_VersionFileSingleSourceOfTruth(t *testing.T) {
	raw, err := os.ReadFile(versionFileAbs(t))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	got := strings.TrimSpace(string(raw))
	if got != version {
		t.Errorf("VERSION file = %q, want %q (version var); bump both together", got, version)
	}
}

// TestInspectSnapshot_JSONShapeSnakeCase is the contract pin for
// fix-readme-snapshot-sample-stale: the non-interactive `inspect -s <id> --json`
// stdout must emit reached_spans with the snake_case keys (`span_id`,
// `name":"agent.invoke`) and must NOT carry the pre-v0.4.0 PascalCase `SpanID`
// key the README still documents. The v0.4.0 encoding fix already makes the
// output snake_case, so this test is green on the current source — it pins the
// README-vs-output contract so the doc cannot silently drift from the code
// again.
func TestInspectSnapshot_JSONShapeSnakeCase(t *testing.T) {
	trace := sampleTraceAbs(t)

	var stdout bytes.Buffer
	root := newRoot()
	root.SetArgs([]string{"inspect", trace, "-s", "0a0b0c0d0e0f0a0b", "--json"})
	root.SetOut(&stdout)
	if err := root.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, `"span_id"`) {
		t.Errorf("stdout reached_spans must contain snake_case \"span_id\" key: got %q", got)
	}
	if !strings.Contains(got, `"name":"agent.invoke"`) {
		t.Errorf("stdout reached_spans must contain \"name\":\"agent.invoke\": got %q", got)
	}
	if strings.Contains(got, `"SpanID"`) {
		t.Errorf("stdout must NOT carry the pre-v0.4.0 PascalCase \"SpanID\" key: got %q", got)
	}
}

// TestREADME_SampleOutputMatchesActualShape is the regression test for
// fix-readme-snapshot-sample-stale: the README.md sample output block must
// document the real snake_case reached_spans shape (`span_id`,
// `name":"agent.invoke`) and must NOT still show the pre-v0.4.0 PascalCase
// shape (`SpanID`/`Name`/`Role`/`Intrusion`). Red on the current README (still
// PascalCase), green once the sample block is updated to match the code.
func TestREADME_SampleOutputMatchesActualShape(t *testing.T) {
	raw, err := os.ReadFile(readmeAbs(t, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	got := string(raw)
	if !strings.Contains(got, `"span_id"`) {
		t.Errorf("README.md sample output must contain snake_case \"span_id\": missing (still pre-v0.4.0 shape?)")
	}
	if !strings.Contains(got, `"name":"agent.invoke"`) {
		t.Errorf("README.md sample output must contain \"name\":\"agent.invoke\": missing")
	}
	if strings.Contains(got, `"SpanID"`) {
		t.Errorf("README.md sample output must NOT contain pre-v0.4.0 PascalCase \"SpanID\": stale sample block")
	}
	if strings.Contains(got, `"Intrusion":true`) {
		t.Errorf("README.md sample output must NOT contain pre-v0.4.0 PascalCase \"Intrusion\": stale sample block")
	}
}

// TestREADME_ZhCNSampleOutputMatchesActualShape is the regression test for
// fix-readme-snapshot-sample-stale (zh-CN half): same contract as the English
// README. Red on the current README.zh-CN.md (still PascalCase), green once
// updated.
func TestREADME_ZhCNSampleOutputMatchesActualShape(t *testing.T) {
	raw, err := os.ReadFile(readmeAbs(t, "README.zh-CN.md"))
	if err != nil {
		t.Fatalf("read README.zh-CN.md: %v", err)
	}
	got := string(raw)
	if !strings.Contains(got, `"span_id"`) {
		t.Errorf("README.zh-CN.md sample output must contain snake_case \"span_id\": missing")
	}
	if !strings.Contains(got, `"name":"agent.invoke"`) {
		t.Errorf("README.zh-CN.md sample output must contain \"name\":\"agent.invoke\": missing")
	}
	if strings.Contains(got, `"SpanID"`) {
		t.Errorf("README.zh-CN.md sample output must NOT contain pre-v0.4.0 PascalCase \"SpanID\": stale sample block")
	}
}

// TestInspect_List_PrintsTree is the regression/feature test for
// feat-inspect-list-tree: `inspect <trace> --list` must return nil and print
// the recorded span tree to stdout (one line per span, indented by depth, with
// the GenAI role tag, span name, intrusion marker, and span id) WITHOUT
// launching the bubbletea TUI. The stdout must contain the pre-marked intrusion
// span id `0a0b0c0d0e0f0a0b`, `agent.invoke`, and `llm.chat`. Red today (no
// `--list` flag -> cobra exits 1 with "unknown flag: --list"), green once the
// flag + RenderTree land.
func TestInspect_List_PrintsTree(t *testing.T) {
	trace := sampleTraceAbs(t)

	var stdout bytes.Buffer
	root := newRoot()
	root.SetArgs([]string{"inspect", trace, "--list"})
	root.SetOut(&stdout)
	if err := root.Execute(); err != nil {
		t.Fatalf("inspect --list: %v (expected nil — the --list flag must exist and exit 0 without the TUI)", err)
	}
	got := stdout.String()
	for _, want := range []string{
		"0a0b0c0d0e0f0a0b", // pre-marked intrusion span id (full, not truncated)
		"agent.invoke",     // root span name
		"llm.chat",         // intrusion span name
	} {
		if !strings.Contains(got, want) {
			t.Errorf("inspect --list stdout missing %q:\n%s", want, got)
		}
	}
}
