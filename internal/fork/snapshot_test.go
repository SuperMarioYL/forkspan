package fork

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

func TestSnapshot_ReachedSpansAreAncestorsPlusSelf(t *testing.T) {
	tr := loadSample(t)
	// Intrusion span = 0a0b0c0d0e0f0a0b (llm.chat). Ancestors: agent.invoke (0102...) + self.
	snap, err := Snapshot(tr, "0a0b0c0d0e0f0a0b")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.AtSpanID != "0a0b0c0d0e0f0a0b" {
		t.Errorf("AtSpanID = %s, want 0a0b0c0d0e0f0a0b", snap.AtSpanID)
	}
	if len(snap.ReachedSpans) != 2 {
		t.Fatalf("len(ReachedSpans) = %d, want 2 (root + intrusion)", len(snap.ReachedSpans))
	}
	// root→leaf order.
	if snap.ReachedSpans[0].SpanID != "0102030405060708" {
		t.Errorf("ReachedSpans[0] = %s, want root", snap.ReachedSpans[0].SpanID)
	}
	if snap.ReachedSpans[1].SpanID != "0a0b0c0d0e0f0a0b" {
		t.Errorf("ReachedSpans[1] = %s, want intrusion span", snap.ReachedSpans[1].SpanID)
	}
}

func TestSnapshot_ReachableToolCallsFromIntrusion(t *testing.T) {
	tr := loadSample(t)
	snap, err := Snapshot(tr, "0a0b0c0d0e0f0a0b")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Downstream of the intrusion llm.chat: bash + http (exfil). The benign
	// search span is under a different llm.chat branch — NOT reachable.
	if len(snap.ReachableToolCalls) != 2 {
		t.Fatalf("len(ReachableToolCalls) = %d, want 2 (bash + http)", len(snap.ReachableToolCalls))
	}
	want := map[string]bool{"1112131415161718": true, "2122232425262728": true}
	for _, id := range snap.ReachableToolCalls {
		if !want[id] {
			t.Errorf("unexpected reachable tool call %s", id)
		}
	}
}

func TestSnapshot_OpaqueAgentStateCopied(t *testing.T) {
	tr := loadSample(t)
	snap, err := Snapshot(tr, "0a0b0c0d0e0f0a0b")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.AgentState) == 0 {
		t.Fatal("AgentState should be a non-empty opaque checkpoint")
	}
}

func TestSnapshot_AtRootReachesAllToolCalls(t *testing.T) {
	tr := loadSample(t)
	snap, err := Snapshot(tr, "0102030405060708")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Forking at the agent root reaches every downstream tool call (3 total).
	if len(snap.ReachableToolCalls) != 3 {
		t.Errorf("len(ReachableToolCalls) at root = %d, want 3", len(snap.ReachableToolCalls))
	}
	if len(snap.ReachedSpans) != 1 {
		t.Errorf("len(ReachedSpans) at root = %d, want 1 (self only)", len(snap.ReachedSpans))
	}
}

func TestSnapshot_UnknownSpanErrors(t *testing.T) {
	tr := loadSample(t)
	if _, err := Snapshot(tr, "deadbeefdeadbeef"); err == nil {
		t.Error("Snapshot on unknown span should error")
	}
	if _, err := Snapshot(tr, ""); err == nil {
		t.Error("Snapshot on empty span should error")
	}
}

func TestSnapshot_MarshalJSON(t *testing.T) {
	tr := loadSample(t)
	snap, err := Snapshot(tr, "0a0b0c0d0e0f0a0b")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	b, err := snap.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("snapshot JSON should be non-empty")
	}
	js := string(b)
	if !contains(js, "at_span_id") {
		t.Error("snapshot JSON should contain at_span_id")
	}
	if !contains(js, "reachable_tool_calls") {
		t.Error("snapshot JSON should contain reachable_tool_calls")
	}
}

func TestSnapshot_SelfCycleParentIDDoesNotHang(t *testing.T) {
	// A span whose parentSpanId == spanId (a malformed / compromised-agent trace)
	// must NOT hang the parent-walk or the children-DFS in Snapshot. Without the
	// visited-set guard this loops forever; with it, the cycle is broken and the
	// self-cycle span is its own only reached span (and its own only reachable
	// tool call). Run with -timeout to catch a regression.
	spans := []ingest.Span{
		{SpanID: "dead0000dead0000", ParentID: "dead0000dead0000", TraceID: "t",
			Name: "tool.call.bash", Role: ingest.RoleTool, ToolName: "bash"},
	}
	tr := ingest.NewTree(spans)
	snap, err := Snapshot(tr, "dead0000dead0000")
	if err != nil {
		t.Fatalf("Snapshot on self-cycle span: %v", err)
	}
	if len(snap.ReachedSpans) != 1 {
		t.Fatalf("len(ReachedSpans) = %d, want 1 (self only, cycle broken)", len(snap.ReachedSpans))
	}
	if snap.ReachedSpans[0].SpanID != "dead0000dead0000" {
		t.Errorf("ReachedSpans[0] = %s, want the self-cycle span", snap.ReachedSpans[0].SpanID)
	}
	if len(snap.ReachableToolCalls) != 1 || snap.ReachableToolCalls[0] != "dead0000dead0000" {
		t.Errorf("ReachableToolCalls = %v, want [dead0000dead0000] (cycle broken)", snap.ReachableToolCalls)
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
