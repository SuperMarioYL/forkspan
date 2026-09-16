package ingest

import (
	"testing"
	"time"
)

// The tests in this file pin ForkSpan's conformance to the OTLP/JSON encoding
// rules (specification/protocol/file-exporter § "JSON Protobuf Encoding"):
//
//   - "Values of enum fields MUST be encoded as integer values" — so `kind`
//     and `status.code` arrive as JSON numbers, not the SPAN_KIND_* /
//     STATUS_CODE_* name strings the older proto3-JSON mapping used.
//   - 64-bit integers "either numbers or strings are accepted when decoding"
//     — so startTimeUnixNano / endTimeUnixNano may arrive as JSON numbers.
//   - traceId/spanId are "represented as case-insensitive hex-encoded strings"
//     (the spec's own example is uppercase), so every ID form must compare
//     equal to its lowercase canonicalization.

// TestLoadBytes_IntegerEnumAndTimestampForms is the regression test for
// fix-otlp-json-integer-enums-timestamps: a trace emitted with the
// spec-mandated integer forms — numeric `kind`, numeric `status.code`, numeric
// int64 timestamps — must parse. On the v0.8.0 source this fixture fails at
// json.Unmarshal ("cannot unmarshal number into Go struct field ... of type
// string") and the whole trace is lost with exit 1.
func TestLoadBytes_IntegerEnumAndTimestampForms(t *testing.T) {
	const numericTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "0102030405060708",
	          "name": "llm.chat",
	          "kind": 1,
	          "startTimeUnixNano": 1785283200000000000,
	          "endTimeUnixNano": 1785283200600000000,
	          "attributes": [
	            { "key": "gen_ai.operation.name", "value": { "stringValue": "chat" } }
	          ],
	          "status": { "code": 2 }
	        }
	      ]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(numericTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v (spec-mandated integer forms must parse)", err)
	}
	if len(tr.Spans) != 1 {
		t.Fatalf("len(Spans) = %d, want 1", len(tr.Spans))
	}
	s := tr.Get("0102030405060708")
	if s == nil {
		t.Fatalf("span 0102030405060708 not indexed")
	}
	if s.Kind != SpanKindInternal {
		t.Errorf("kind = %v, want SPAN_KIND_INTERNAL (integer enum 1)", s.Kind)
	}
	if s.Status.Code != StatusError {
		t.Errorf("status.code = %v, want STATUS_CODE_ERROR (integer enum 2)", s.Status.Code)
	}
	wantStart := time.Unix(0, 1785283200000000000).UTC()
	if !s.Start.Equal(wantStart) {
		t.Errorf("start = %v, want %v (numeric int64 nanos)", s.Start, wantStart)
	}
	wantEnd := time.Unix(0, 1785283200600000000).UTC()
	if !s.End.Equal(wantEnd) {
		t.Errorf("end = %v, want %v (numeric int64 nanos)", s.End, wantEnd)
	}
}

// TestLoadBytes_StringEnumStillAccepted pins backward compatibility: the name
// string forms ("SPAN_KIND_INTERNAL", "STATUS_CODE_OK") used by the bundled
// sample trace and docs must keep parsing alongside the integer forms.
func TestLoadBytes_StringEnumStillAccepted(t *testing.T) {
	const stringTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "0102030405060708",
	          "name": "llm.chat",
	          "kind": "SPAN_KIND_SERVER",
	          "startTimeUnixNano": "1785283200000000000",
	          "endTimeUnixNano": "1785283200600000000",
	          "status": { "code": "STATUS_CODE_OK" }
	        }
	      ]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(stringTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	s := tr.Get("0102030405060708")
	if s == nil {
		t.Fatalf("span 0102030405060708 not indexed")
	}
	if s.Kind != SpanKindServer {
		t.Errorf("kind = %v, want SPAN_KIND_SERVER", s.Kind)
	}
	if s.Status.Code != StatusOK {
		t.Errorf("status.code = %v, want STATUS_CODE_OK", s.Status.Code)
	}
}

// TestLoadBytes_HexIDsCaseInsensitive is the regression test for
// fix-hex-ids-case-insensitive: OTLP/JSON hex IDs are case-insensitive per the
// spec, so a span stored with an uppercase spanId must link to a child whose
// parentSpanId is lowercase (and vice versa) instead of silently losing the
// parent→child edge, and IDs must canonicalize to lowercase so queries and
// --list output agree regardless of the case a producer emitted.
func TestLoadBytes_HexIDsCaseInsensitive(t *testing.T) {
	// Parent stored with UPPERCASE ids; child references it lowercase (and the
	// second child is stored uppercase while referencing lowercase) — both are
	// the same ID case-insensitively.
	const mixedCaseTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899AABBCCDDEEFF",
	          "spanId": "0A0B0C0D0E0F0A0B",
	          "name": "llm.chat",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200000000000",
	          "attributes": [
	            { "key": "gen_ai.operation.name", "value": { "stringValue": "chat" } }
	          ]
	        },
	        {
	          "traceId": "00112233445566778899AABBCCDDEEFF",
	          "spanId": "1112131415161718",
	          "parentSpanId": "0a0b0c0d0e0f0a0b",
	          "name": "tool.call.bash",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200300000000",
	          "attributes": [
	            { "key": "gen_ai.operation.name", "value": { "stringValue": "execute_tool" } },
	            { "key": "gen_ai.tool.name", "value": { "stringValue": "bash" } }
	          ]
	        }
	      ]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(mixedCaseTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	// IDs canonicalize to lowercase.
	if tr.Get("0A0B0C0D0E0F0A0B") != nil {
		t.Errorf("uppercase lookup must miss after canonicalization (ids are lowercase)")
	}
	s := tr.Get("0a0b0c0d0e0f0a0b")
	if s == nil {
		t.Fatalf("span 0a0b0c0d0e0f0a0b not indexed (lowercase canonical id)")
	}
	// The child must remain a CHILD (parent→child edge intact), not be
	// re-rooted by the orphan predicate.
	if kids := tr.Children("0a0b0c0d0e0f0a0b"); len(kids) != 1 || kids[0] != "1112131415161718" {
		t.Fatalf("Children(lowercase parent id) = %v, want [1112131415161718] (mixed-case edge must survive)", kids)
	}
	roots := tr.Roots()
	if len(roots) != 1 || roots[0] != "0a0b0c0d0e0f0a0b" {
		t.Fatalf("Roots = %v, want only the llm.chat root (child must not be re-rooted)", roots)
	}
}

// TestTree_RootsIncludeCycleBoundSpans is the regression test for
// fix-cycle-spans-invisible-in-navigator: spans trapped in a parent cycle
// (self-loop, or a mutual A↔B loop) can never be reached by walking down from
// a real root, so Roots() must surface them (once each) instead of silently
// dropping them from the navigator and `inspect --list`. On the v0.8.0 source
// both fixtures produce empty Roots().
func TestTree_RootsIncludeCycleBoundSpans(t *testing.T) {
	const selfLoopTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "0a0b0c0d0e0f0a0b",
	          "parentSpanId": "0a0b0c0d0e0f0a0b",
	          "name": "llm.chat",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200000000000",
	          "attributes": [
	            { "key": "forkspan.intrusion", "value": { "boolValue": true } }
	          ]
	        }
	      ]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(selfLoopTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	roots := tr.Roots()
	if len(roots) != 1 || roots[0] != "0a0b0c0d0e0f0a0b" {
		t.Fatalf("self-loop Roots = %v, want [0a0b0c0d0e0f0a0b] (the only span must stay visible)", roots)
	}
	if tr.IntrusionSpan() != "0a0b0c0d0e0f0a0b" {
		t.Fatalf("IntrusionSpan = %q, want the self-loop span (must stay discoverable)", tr.IntrusionSpan())
	}

	const mutualCycleTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "aaaaaaaaaaaaaaaa",
	          "parentSpanId": "bbbbbbbbbbbbbbbb",
	          "name": "llm.chat",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200000000000"
	        },
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "bbbbbbbbbbbbbbbb",
	          "parentSpanId": "aaaaaaaaaaaaaaaa",
	          "name": "tool.call.bash",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200300000000",
	          "attributes": [
	            { "key": "gen_ai.tool.name", "value": { "stringValue": "bash" } }
	          ]
	        }
	      ]
	    }]
	  }]
	}`
	tr2, err := LoadBytes([]byte(mutualCycleTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	roots2 := tr2.Roots()
	if len(roots2) != 2 {
		t.Fatalf("mutual-cycle Roots = %v, want both spans exactly once each", roots2)
	}
	got := map[string]bool{roots2[0]: true, roots2[1]: true}
	if !got["aaaaaaaaaaaaaaaa"] || !got["bbbbbbbbbbbbbbbb"] {
		t.Fatalf("mutual-cycle Roots = %v, want {aaaaaaaaaaaaaaaa, bbbbbbbbbbbbbbbb}", roots2)
	}
}

// TestTree_RootsWellFormedUnchangedByCycleCheck guards the cycle fix against
// over-rooting: a well-formed chain (root → child → grandchild) still yields
// exactly one root, and no span is reported twice.
func TestTree_RootsWellFormedUnchangedByCycleCheck(t *testing.T) {
	tr := loadSample(t)
	roots := tr.Roots()
	if len(roots) != 1 || roots[0] != "0102030405060708" {
		t.Fatalf("Roots = %v, want [0102030405060708] (well-formed sample unchanged)", roots)
	}
}
