package ingest

import (
	"encoding/json"
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

// TestLoadBytes_ModelInvocationOperationsClassifiedLLM is the regression test
// for fix-genai-operation-role-mapping: the OTel-GenAI semconv defines
// text_completion and embeddings alongside chat / execute_tool / invoke_agent,
// and a conforming exporter names the span "{operation} {model}". Pre-fix the
// role switch only knew chat/execute_tool/invoke_agent, so these fell through to
// inferRole(name) — where "text_completion frontier-lab-8b" matches neither
// "chat" nor "llm" — and the span rendered as RoleUnknown ("[span]") in
// `inspect --list` instead of RoleLLM.
func TestLoadBytes_ModelInvocationOperationsClassifiedLLM(t *testing.T) {
	cases := []struct{ op, name string }{
		{"text_completion", "text_completion frontier-lab-8b"},
		{"embeddings", "embeddings text-embedding-3"},
	}
	for _, tc := range cases {
		trace := `{
		  "resourceSpans": [{
		    "scopeSpans": [{
		      "spans": [{
		        "traceId": "00112233445566778899aabbccddeeff",
		        "spanId": "77cc77cc77cc77cc",
		        "name": "` + tc.name + `",
		        "kind": "SPAN_KIND_INTERNAL",
		        "startTimeUnixNano": "1785283200100000000",
		        "endTimeUnixNano": "1785283200150000000",
		        "attributes": [
		          { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
		          { "key": "gen_ai.operation.name", "value": { "stringValue": "` + tc.op + `" } }
		        ],
		        "status": { "code": "STATUS_CODE_OK" }
		      }]
		    }]
		  }]
		}`
		tr, err := LoadBytes([]byte(trace))
		if err != nil {
			t.Fatalf("LoadBytes(%s): %v", tc.op, err)
		}
		s := tr.Get("77cc77cc77cc77cc")
		if s == nil {
			t.Fatalf("missing span for %s", tc.op)
		}
		if s.Role != RoleLLM {
			t.Errorf("gen_ai.operation.name=%q (span %q) Role = %q, want %q", tc.op, tc.name, s.Role, RoleLLM)
		}
		if s.IsToolCall() {
			t.Errorf("gen_ai.operation.name=%q must not classify as a tool call", tc.op)
		}
	}
}

// TestLoadBytes_NonFiniteDoubleValueForms is the regression test for
// fix-nonfinite-double-value-parse: proto3 JSON encodes the non-finite doubles
// as the strings "NaN" / "Infinity" / "-Infinity" (verified against
// google.golang.org/protobuf's own JSON encoder), so a spec-legal non-finite
// double attribute must not abort the whole parse. Pre-fix the wire struct typed
// doubleValue as *float64, so one such attribute made json.Unmarshal fail with
// "cannot unmarshal string into Go struct field ... doubleValue of type float64"
// and the entire trace was lost.
func TestLoadBytes_NonFiniteDoubleValueForms(t *testing.T) {
	for _, special := range []string{"NaN", "Infinity", "-Infinity"} {
		trace := `{
		  "resourceSpans": [{
		    "scopeSpans": [{
		      "spans": [{
		        "traceId": "00112233445566778899aabbccddeeff",
		        "spanId": "88dd88dd88dd88dd",
		        "name": "llm.chat",
		        "kind": "SPAN_KIND_INTERNAL",
		        "startTimeUnixNano": "1785283200100000000",
		        "endTimeUnixNano": "1785283200150000000",
		        "attributes": [
		          { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
		          { "key": "gen_ai.operation.name", "value": { "stringValue": "chat" } },
		          { "key": "gen_ai.request.temperature", "value": { "doubleValue": "` + special + `" } }
		        ],
		        "status": { "code": "STATUS_CODE_OK" }
		      }]
		    }]
		  }]
		}`
		tr, err := LoadBytes([]byte(trace))
		if err != nil {
			t.Fatalf("LoadBytes(doubleValue=%q): %v (one non-finite attribute must not lose the trace)", special, err)
		}
		s := tr.Get("88dd88dd88dd88dd")
		if s == nil {
			t.Fatalf("span lost for doubleValue=%q", special)
		}
		// The value is kept as its wire string: encoding/json cannot marshal a
		// Go NaN/Inf, so the snapshot must stay marshallable.
		if got := s.AttrString("gen_ai.request.temperature"); got != special {
			t.Errorf("doubleValue=%q: attr value = %q, want the wire string %q", special, got, special)
		}
		if _, err := json.Marshal(s); err != nil {
			t.Errorf("doubleValue=%q: span must stay JSON-marshalable: %v", special, err)
		}
	}
}

// TestLoadBytes_FiniteDoubleValueUnchanged guards the non-regressed half of
// fix-nonfinite-double-value-parse: a finite double still parses as a number
// (not the wire token string), and a non-numeric string form is still rejected
// rather than silently accepted.
func TestLoadBytes_FiniteDoubleValueUnchanged(t *testing.T) {
	const finiteTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [{
	        "traceId": "00112233445566778899aabbccddeeff",
	        "spanId": "88dd88dd88dd88dd",
	        "name": "llm.chat",
	        "kind": "SPAN_KIND_INTERNAL",
	        "startTimeUnixNano": "1785283200100000000",
	        "endTimeUnixNano": "1785283200150000000",
	        "attributes": [
	          { "key": "gen_ai.request.temperature", "value": { "doubleValue": 0.7 } }
	        ],
	        "status": { "code": "STATUS_CODE_OK" }
	      }]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(finiteTrace))
	if err != nil {
		t.Fatalf("LoadBytes(finite double): %v", err)
	}
	kv, ok := tr.Get("88dd88dd88dd88dd").Attr("gen_ai.request.temperature")
	if !ok {
		t.Fatal("missing temperature attribute")
	}
	if f, isFloat := kv.Value.(float64); !isFloat || f != 0.7 {
		t.Errorf("finite doubleValue = %#v, want float64(0.7)", kv.Value)
	}

	const bogusTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [{
	        "traceId": "00112233445566778899aabbccddeeff",
	        "spanId": "88dd88dd88dd88dd",
	        "name": "llm.chat",
	        "attributes": [
	          { "key": "gen_ai.request.temperature", "value": { "doubleValue": "lukewarm" } }
	        ]
	      }]
	    }]
	  }]
	}`
	if _, err := LoadBytes([]byte(bogusTrace)); err == nil {
		t.Error("a non-numeric doubleValue string must still be rejected, not silently accepted")
	}
}

// TestLoadBytes_RejectsEmptySpanID is the regression test for
// fix-empty-span-id-hijacks-root-sentinel (parse boundary): spanId is the
// identity every surface keys on and "" is the model's "no parent" sentinel, so
// an export containing a span record without one must be reported instead of
// ingested. Pre-fix the record was indexed as byID[""], which made every real
// root's empty parentSpanId resolve to it (phantom ancestors) and re-parented
// the fragment into another span's subtree.
func TestLoadBytes_RejectsEmptySpanID(t *testing.T) {
	const trace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "aaaa0000aaaa0000",
	          "name": "agent.invoke",
	          "startTimeUnixNano": "1785283200000000000"
	        },
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "",
	          "parentSpanId": "aaaa0000aaaa0000",
	          "name": "unidentified.fragment",
	          "startTimeUnixNano": "1785283200100000000"
	        }
	      ]
	    }]
	  }]
	}`
	_, err := LoadBytes([]byte(trace))
	if err == nil {
		t.Fatal("LoadBytes must reject a span record with an empty spanId, not ingest it")
	}
	if !contains(err.Error(), "spanId") {
		t.Errorf("error = %q, want it to name the empty spanId", err)
	}
}

// TestNewTree_EmptySpanIDNotIndexed is the model-level guard for
// fix-empty-span-id-hijacks-root-sentinel: even when a caller hands NewTree a
// span with no id (the proto/interop seam bypasses the LoadBytes check), the
// empty id must never become a lookup key or a child edge, so every root keeps
// exactly the ancestors it recorded.
func TestNewTree_EmptySpanIDNotIndexed(t *testing.T) {
	tr := NewTree([]Span{
		{SpanID: "aaaa0000aaaa0000", Name: "agent.invoke"},
		{SpanID: "", ParentID: "aaaa0000aaaa0000", Name: "unidentified.fragment"},
	})
	if tr.Get("") != nil {
		t.Fatal(`Tree.Get("") must be nil: "" is the no-parent sentinel, never a span id`)
	}
	roots := tr.Roots()
	if len(roots) != 1 || roots[0] != "aaaa0000aaaa0000" {
		t.Fatalf("Roots = %v, want only [aaaa0000aaaa0000]", roots)
	}
	for _, kid := range tr.Children("aaaa0000aaaa0000") {
		if kid == "" {
			t.Error(`Children must not contain the empty id`)
		}
	}
}
