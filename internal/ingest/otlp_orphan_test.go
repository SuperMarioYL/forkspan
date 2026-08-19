package ingest

import "testing"

// TestTree_RootsIncludeOrphans is the regression test for
// fix-orphan-spans-invisible-in-navigator: a span whose parentSpanId points at
// a span absent from the export (a dangling/orphan parent — OTLP-spec-allowed
// for partial collector grabs of compromised-agent runs) must still surface as a
// root in Roots(), so the TUI navigator and `inspect --list` don't silently drop
// it (incl. a pre-marked forkspan.intrusion span). Without the fix, Roots() only
// returned spans with ParentID == "" and the orphan was invisible.
func TestTree_RootsIncludeOrphans(t *testing.T) {
	const orphanTrace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "deadbeefdeadbeef",
	          "parentSpanId": "ffffffffffffffff",
	          "name": "llm.chat",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200100000000",
	          "endTimeUnixNano": "1785283200150000000",
	          "attributes": [
	            { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
	            { "key": "forkspan.intrusion", "value": { "boolValue": true } }
	          ],
	          "status": { "code": "STATUS_CODE_OK" }
	        }
	      ]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(orphanTrace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	roots := tr.Roots()
	if len(roots) != 1 {
		t.Fatalf("len(Roots) = %d, want 1 (orphan span must surface as a root)", len(roots))
	}
	if roots[0] != "deadbeefdeadbeef" {
		t.Fatalf("root = %s, want deadbeefdeadbeef", roots[0])
	}
	// The pre-marked intrusion span must remain discoverable via Roots() so
	// `inspect --list` honors the m1 contract (discover span IDs incl. the
	// pre-marked intrusion span).
	if tr.IntrusionSpan() != "deadbeefdeadbeef" {
		t.Fatalf("IntrusionSpan = %s, want deadbeefdeadbeef", tr.IntrusionSpan())
	}
}

// TestTree_RootsNoFalsePositivesForPresentParents guards the same fix against
// over-rooting: a span whose parent IS present in the export must NOT become a
// root (the fix is behavior-preserving for well-formed trees).
func TestTree_RootsNoFalsePositivesForPresentParents(t *testing.T) {
	// root (no parent) -> child (parent present) ; only root is a root.
	const trace = `{
	  "resourceSpans": [{
	    "scopeSpans": [{
	      "spans": [
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "1111111111111111",
	          "name": "agent.invoke",
	          "kind": "SPAN_KIND_INTERNAL",
	          "startTimeUnixNano": "1785283200100000000",
	          "endTimeUnixNano": "1785283200200000000",
	          "attributes": [
	            { "key": "gen_ai.system", "value": { "stringValue": "demo" } }
	          ],
	          "status": { "code": "STATUS_CODE_OK" }
	        },
	        {
	          "traceId": "00112233445566778899aabbccddeeff",
	          "spanId": "2222222222222222",
	          "parentSpanId": "1111111111111111",
	          "name": "tool.call.bash",
	          "kind": "SPAN_KIND_CLIENT",
	          "startTimeUnixNano": "1785283200120000000",
	          "endTimeUnixNano": "1785283200150000000",
	          "attributes": [
	            { "key": "gen_ai.system", "value": { "stringValue": "demo" } },
	            { "key": "gen_ai.tool.name", "value": { "stringValue": "bash" } }
	          ],
	          "status": { "code": "STATUS_CODE_OK" }
	        }
	      ]
	    }]
	  }]
	}`
	tr, err := LoadBytes([]byte(trace))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	roots := tr.Roots()
	if len(roots) != 1 {
		t.Fatalf("len(Roots) = %d, want 1 (child whose parent is present must not root)", len(roots))
	}
	if roots[0] != "1111111111111111" {
		t.Fatalf("root = %s, want 1111111111111111", roots[0])
	}
}
