package ingest

import (
	"testing"
)

const samplePath = "../../testdata/sample-compromised-trace.json"

func loadSample(t *testing.T) *Tree {
	t.Helper()
	tr, err := LoadFile(samplePath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return tr
}

func TestLoadBytes_ParsesAllSpans(t *testing.T) {
	tr := loadSample(t)
	// The fixture has 6 spans: 1 agent + 2 llm + 3 tool calls.
	if got := len(tr.Spans); got != 6 {
		t.Fatalf("len(Spans) = %d, want 6", got)
	}
}

func TestTree_RootsAndChildren(t *testing.T) {
	tr := loadSample(t)
	roots := tr.Roots()
	if len(roots) != 1 {
		t.Fatalf("len(Roots) = %d, want 1", len(roots))
	}
	if roots[0] != "0102030405060708" {
		t.Fatalf("root = %s, want 0102030405060708", roots[0])
	}
	kids := tr.Children("0102030405060708")
	// agent.invoke has two children: the intrusion llm.chat and the benign llm.chat.
	if len(kids) != 2 {
		t.Fatalf("root children = %d, want 2", len(kids))
	}
}

func TestSpan_GenAIRoleDerivedFromAttributes(t *testing.T) {
	tr := loadSample(t)
	cases := map[string]GenAIRole{
		"0102030405060708": RoleAgent, // agent.invoke → invoke_agent
		"0a0b0c0d0e0f0a0b": RoleLLM,   // llm.chat → chat (intrusion span)
		"1112131415161718": RoleTool,  // tool.call.bash → execute_tool
		"2122232425262728": RoleTool,  // tool.call.http
		"4142434445464748": RoleTool,  // tool.call.search
	}
	for id, want := range cases {
		s := tr.Get(id)
		if s == nil {
			t.Fatalf("missing span %s", id)
		}
		if s.Role != want {
			t.Errorf("span %s role = %q, want %q", id, s.Role, want)
		}
	}
}

func TestSpan_ToolNameLifted(t *testing.T) {
	tr := loadSample(t)
	bash := tr.Get("1112131415161718")
	if bash.ToolName != "bash" {
		t.Errorf("bash.ToolName = %q, want bash", bash.ToolName)
	}
	if !bash.IsToolCall() {
		t.Error("bash span should be a tool call")
	}
}

func TestIntrusionSpan_PreMarked(t *testing.T) {
	tr := loadSample(t)
	got := tr.IntrusionSpan()
	if got != "0a0b0c0d0e0f0a0b" {
		t.Fatalf("IntrusionSpan = %s, want 0a0b0c0d0e0f0a0b", got)
	}
	if !tr.Get(got).Intrusion {
		t.Error("intrusion span should carry Intrusion=true")
	}
}

func TestLoadBytes_RejectsEmpty(t *testing.T) {
	if _, err := LoadBytes(nil); err == nil {
		t.Error("LoadBytes(nil) should error")
	}
}

func TestToolCalls_OrderedByStart(t *testing.T) {
	tr := loadSample(t)
	tc := tr.ToolCalls()
	if len(tc) != 3 {
		t.Fatalf("len(ToolCalls) = %d, want 3", len(tc))
	}
	// bash starts before http before search.
	want := []string{"1112131415161718", "2122232425262728", "4142434445464748"}
	for i, w := range want {
		if tc[i].SpanID != w {
			t.Errorf("ToolCalls[%d] = %s, want %s", i, tc[i].SpanID, w)
		}
	}
}
