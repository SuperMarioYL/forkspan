// Package fork implements the intrusion-fork-tree primitive: a tree whose
// root is the StateSnapshot taken at the intrusion span and whose children
// are counterfactual branches.
//
// The m1 milestone implements the snapshot half only — Snapshot() captures
// the recorded state reachable at a span and is dumped to stdout by the
// `inspect` navigator. Counterfactual projection is the m2 milestone
// (see counterfactual.go).
package fork

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/SuperMarioYL/forkspan/internal/ingest"
)

// MutationKind enumerates the counterfactual mutations an operator can apply
// at a fork point. Used by m2; declared here so the StateSnapshot primitive
// can reference its own vocabulary.
type MutationKind int

const (
	MutationBlockTool MutationKind = iota + 1
	MutationRedactPayload
	MutationHardenPolicy
)

// String renders a MutationKind for display.
func (m MutationKind) String() string {
	switch m {
	case MutationBlockTool:
		return "block_tool"
	case MutationRedactPayload:
		return "redact_payload"
	case MutationHardenPolicy:
		return "harden_policy"
	}
	return "unknown"
}

// Mutation is a single counterfactual edit applied to a StateSnapshot.
// Projected by the m2 counterfactual engine (counterfactual.go).
type Mutation struct {
	Kind         MutationKind
	TargetSpanID string
	Payload      []byte
}

// StateSnapshot is the recorded agent state captured at the intrusion span.
// It is the root of the intrusion-fork-tree.
//
//   - ReachedSpans are the ancestors of (and including) AtSpanID, in
//     root→leaf order — the spans whose state was already settled when the
//     intrusion landed.
//   - ReachableToolCalls is the forward-reachable tool-call set: every
//     Role==Tool span downstream of AtSpanID, in start order. This is the
//     subgraph a counterfactual would project (and diff against).
//   - AgentState is an opaque checkpoint copied verbatim; ForkSpan v0.1 does
//     not interpret it.
type StateSnapshot struct {
	AtSpanID            string       `json:"at_span_id"`
	ReachedSpans        []ingest.Span `json:"reached_spans"`
	ReachableToolCalls  []string     `json:"reachable_tool_calls"`
	AgentState          []byte       `json:"agent_state"`
}

// Snapshot captures the recorded state at atSpanID. It is a pure function
// over the span tree — no execution, no network.
func Snapshot(tree *ingest.Tree, atSpanID string) (StateSnapshot, error) {
	if atSpanID == "" {
		return StateSnapshot{}, fmt.Errorf("fork: empty span id")
	}
	root := tree.Get(atSpanID)
	if root == nil {
		return StateSnapshot{}, fmt.Errorf("fork: span %q not in tree", atSpanID)
	}

	// Reached spans: walk up the parent chain, then reverse to root→leaf.
	// Guard against a cyclic / self-referential ParentID (a malformed or
	// compromised-agent trace) so the walk terminates instead of hanging —
	// a span whose parentSpanId == spanId must not loop forever here.
	var chain []string
	seen := map[string]bool{}
	for cur := tree.Get(atSpanID); cur != nil && !seen[cur.SpanID]; cur = tree.Get(cur.ParentID) {
		seen[cur.SpanID] = true
		chain = append(chain, cur.SpanID)
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	reached := make([]ingest.Span, 0, len(chain))
	for _, id := range chain {
		reached = append(reached, *tree.Get(id))
	}

	// Reachable tool-calls: DFS from atSpanID's children, collect tool spans.
	// Guard against a cyclic ParentID among descendants (mirrors diff.Subgraph's
	// `seen` set) so a malformed trace cannot make the DFS recurse forever.
	var reachable []string
	seenKids := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		for _, cid := range tree.Children(id) {
			if seenKids[cid] {
				continue
			}
			seenKids[cid] = true
			c := tree.Get(cid)
			if c == nil {
				continue
			}
			if c.IsToolCall() {
				reachable = append(reachable, c.SpanID)
			}
			walk(cid)
		}
	}
	walk(atSpanID)
	sort.SliceStable(reachable, func(i, j int) bool {
		a, b := tree.Get(reachable[i]), tree.Get(reachable[j])
		return a.Start.Before(b.Start)
	})

	// Opaque agent-state checkpoint: the reached spans' name+role+attrs,
	// serialized verbatim. ForkSpan does not interpret this; it is copied.
	ckpt, _ := json.Marshal(struct {
		Spans []ingest.Span `json:"reached_spans"`
	}{Spans: reached})

	return StateSnapshot{
		AtSpanID:           atSpanID,
		ReachedSpans:       reached,
		ReachableToolCalls: reachable,
		AgentState:         ckpt,
	}, nil
}

// MarshalJSON renders the snapshot as JSON for the `--json` dump path.
func (s StateSnapshot) MarshalJSON() ([]byte, error) {
	type out struct {
		AtSpanID           string         `json:"at_span_id"`
		ReachedSpans       []ingest.Span  `json:"reached_spans"`
		ReachableToolCalls []string       `json:"reachable_tool_calls"`
		AgentState         json.RawMessage `json:"agent_state"`
	}
	o := out{
		AtSpanID:           s.AtSpanID,
		ReachedSpans:       s.ReachedSpans,
		ReachableToolCalls: s.ReachableToolCalls,
		AgentState:         json.RawMessage(s.AgentState),
	}
	return json.Marshal(o)
}
