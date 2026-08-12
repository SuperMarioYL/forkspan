package ingest

import (
	"encoding/json"
	"testing"
	"time"
)

// TestSpan_MarshalJSON_SnakeCaseKeys is the regression test for
// fix-snapshot-reachedspans-encoding (field-name half): a Span must marshal
// with snake_case json keys, because the snapshot's MarshalJSON embeds
// []Span verbatim for reached_spans and the snapshot's own top level is
// snake_case by design (at_span_id / reached_spans / reachable_tool_calls /
// agent_state). Pre-fix model.go carried no json tags, so Go's default marshal
// emitted PascalCase (SpanID / ParentID / Kind / Status / ...), diverging from
// the top level; this test fails on that code.
func TestSpan_MarshalJSON_SnakeCaseKeys(t *testing.T) {
	s := Span{
		SpanID:    "0a0b0c0d0e0f0a0b",
		ParentID:  "0102030405060708",
		TraceID:   "00112233445566778899aabbccddeeff",
		Kind:      SpanKindInternal,
		Name:      "llm.chat",
		ToolName:  "bash",
		Role:      RoleTool,
		Attrs:     []KeyValue{{Key: "gen_ai.system", Value: "demo"}},
		Start:     time.Unix(0, 1785283200100000000).UTC(),
		End:       time.Unix(0, 1785283200300000000).UTC(),
		Status:    Status{Code: StatusOK, Message: "ok"},
		Intrusion: true,
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, k := range []string{"SpanID", "ParentID", "TraceID", "Kind", "Name", "ToolName", "Role", "Attrs", "Start", "End", "Status", "Intrusion"} {
		if _, ok := m[k]; ok {
			t.Errorf("found PascalCase key %q in span JSON (want snake_case json tags); got %s", k, b)
		}
	}
	for _, k := range []string{"span_id", "parent_id", "trace_id", "kind", "name", "tool_name", "role", "attrs", "start", "end", "status", "intrusion"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing snake_case key %q in span JSON; got %s", k, b)
		}
	}
}

// TestSpan_MarshalJSON_StringEnumValues is the regression test for
// fix-snapshot-reachedspans-encoding (enum half): SpanKind and StatusCode must
// marshal as the OTLP canonical string enums ("SPAN_KIND_INTERNAL",
// "STATUS_CODE_OK") so the snapshot's reached_spans stay symmetric with the
// parser's string-enum input (spanKindFromString / statusCodeFromString read
// these exact tokens). Pre-fix the kinds had no MarshalJSON and emitted raw
// ints (Kind=1, Status.Code=1), making the primary forensic artifact opaque
// to any JSON reader (1 = OK? INTERNAL?); this test fails on that code.
func TestSpan_MarshalJSON_StringEnumValues(t *testing.T) {
	s := Span{
		Kind:   SpanKindInternal,
		Status: Status{Code: StatusOK, Message: "ok"},
		Attrs:  []KeyValue{{Key: "k", Value: "v"}},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// kind must be the string "SPAN_KIND_INTERNAL", not the raw int 1.
	kind, ok := m["kind"]
	if !ok {
		t.Fatalf("missing snake_case \"kind\"; got %s", b)
	}
	if ks, _ := kind.(string); ks != "SPAN_KIND_INTERNAL" {
		t.Errorf("kind = %v (%T), want string \"SPAN_KIND_INTERNAL\"; got %s", kind, kind, b)
	}

	// status must be a snake_case object whose code is the string enum.
	st, ok := m["status"].(map[string]any)
	if !ok {
		t.Fatalf("status is not a JSON object; got %s", b)
	}
	if _, ok := st["Code"]; ok {
		t.Errorf("found PascalCase status.Code (want snake_case \"code\"); got %s", b)
	}
	code, ok := st["code"]
	if !ok {
		t.Fatalf("status.code missing (want snake_case \"code\"); got %s", b)
	}
	if cs, _ := code.(string); cs != "STATUS_CODE_OK" {
		t.Errorf("status.code = %v (%T), want string \"STATUS_CODE_OK\"; got %s", code, code, b)
	}
	if _, ok := st["message"]; !ok {
		t.Errorf("status.message missing (want snake_case \"message\"); got %s", b)
	}

	// KeyValue must be snake_case too.
	if attrs, ok := m["attrs"].([]any); ok && len(attrs) > 0 {
		if kv, ok := attrs[0].(map[string]any); ok {
			if _, ok := kv["key"]; !ok {
				t.Errorf("attr missing snake_case \"key\"; got %s", b)
			}
			if _, ok := kv["Key"]; ok {
				t.Errorf("found PascalCase attr \"Key\" (want \"key\"); got %s", b)
			}
		}
	}
}
