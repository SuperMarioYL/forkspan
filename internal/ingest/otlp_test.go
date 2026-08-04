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

// TestInferRole_ToolPrecedenceOverChat is the regression test for
// fix-inferrole-tool-misclass: a span named "tool.chat" with no
// gen_ai.operation.name must classify as Tool (not LLM) and lift its
// gen_ai.tool.name, so it is not silently dropped from the tool-call
// subgraph. Genuine LLM spans ("llm.chat" / "chat") keep their classification.
func TestInferRole_ToolPrecedenceOverChat(t *testing.T) {
	const toolChatTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [{
	        "traceId": "00112233445566778899aabbccddeeff",
	        "spanId": "99aa99aa99aa99aa",
	        "name": "tool.chat",
	        "kind": "SPAN_KIND_CLIENT",
	        "startTimeUnixNano": "1785283200100000000",
	        "endTimeUnixNano": "1785283200150000000",
	        "attributes": [
	          { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
	          { "key": "gen_ai.tool.name", "value": { "stringValue": "chat-tool" } }
	        ],
	        "status": { "code": "STATUS_CODE_OK" }
	      }]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(toolChatTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	s := tr.Get("99aa99aa99aa99aa")
	if s == nil {
		t.Fatal("missing span")
	}
	if s.Role != RoleTool {
		t.Errorf("tool.chat Role = %q, want %q (Tool must win over bare \"chat\")", s.Role, RoleTool)
	}
	if s.ToolName != "chat-tool" {
		t.Errorf("ToolName = %q, want \"chat-tool\" (gen_ai.tool.name must lift in the fallback path)", s.ToolName)
	}
	if !s.IsToolCall() {
		t.Error("span should be a tool call (must stay in the tool-call subgraph)")
	}
	// Genuine LLM spans with no gen_ai.operation.name must still classify LLM.
	for _, name := range []string{"llm.chat", "chat"} {
		llmTrace := `{
		  "resourceSpans": [{
		    "scopeSpans": [{
		      "spans": [{
		        "traceId": "00112233445566778899aabbccddeeff",
		        "spanId": "aa11aa11aa11aa11",
		        "name": "` + name + `",
		        "kind": "SPAN_KIND_INTERNAL",
		        "startTimeUnixNano": "1785283200100000000",
		        "endTimeUnixNano": "1785283200150000000",
		        "attributes": [
		          { "key": "gen_ai.system", "value": { "stringValue": "demo" } }
		        ],
		        "status": { "code": "STATUS_CODE_OK" }
		      }]
		    }]
		  }]
		}`
		lt, err := LoadBytes([]byte(llmTrace))
		if err != nil {
			t.Fatalf("LoadBytes(%q): %v", name, err)
		}
		l := lt.Get("aa11aa11aa11aa11")
		if l.Role != RoleLLM {
			t.Errorf("%q Role = %q, want %q (genuine LLM classification must be preserved)", name, l.Role, RoleLLM)
		}
	}
}
