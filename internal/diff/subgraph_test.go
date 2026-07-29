package diff

import (
	"testing"

	"github.com/SuperMarioYL/forkspan/internal/ingest"
)

const samplePath = "../../testdata/sample-compromised-trace.json"

func loadSample(t *testing.T) *ingest.Tree {
	t.Helper()
	tr, err := ingest.LoadFile(samplePath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return tr
}

func TestSubgraph_DownstreamOfIntrusion(t *testing.T) {
	tr := loadSample(t)
	sg := Subgraph(tr, "0a0b0c0d0e0f0a0b")
	// Only the bash + http tool calls live downstream of the intrusion span.
	if len(sg) != 2 {
		t.Fatalf("len(Subgraph) = %d, want 2", len(sg))
	}
	for _, s := range sg {
		if !s.IsToolCall() {
			t.Errorf("subgraph entry %s is not a tool call", s.SpanID)
		}
	}
}

func TestSubgraph_AtRootReachesAllTools(t *testing.T) {
	tr := loadSample(t)
	sg := Subgraph(tr, "0102030405060708")
	if len(sg) != 3 {
		t.Fatalf("len(Subgraph) at root = %d, want 3", len(sg))
	}
}

func TestSubgraph_UnknownSpanEmpty(t *testing.T) {
	tr := loadSample(t)
	if got := Subgraph(tr, "deadbeefdeadbeef"); len(got) != 0 {
		t.Errorf("Subgraph on unknown span should be empty, got %d", len(got))
	}
}

func TestRenderSubgraph_FormatsLines(t *testing.T) {
	tr := loadSample(t)
	out := RenderSubgraph(Subgraph(tr, "0a0b0c0d0e0f0a0b"))
	if out == "" || out == "(no downstream tool calls)" {
		t.Fatalf("RenderSubgraph = %q, want formatted lines", out)
	}
	if !contains(out, "bash") {
		t.Errorf("RenderSubgraph should mention the bash tool: %q", out)
	}
}

func TestDiff_NotImplemented(t *testing.T) {
	if _, err := Diff(nil, nil); err == nil {
		t.Error("Diff should return ErrDiffNotImplemented in m1")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
