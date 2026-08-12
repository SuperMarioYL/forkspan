// Package ingest defines ForkSpan's in-memory span model and the OTLP-GenAI
// importer that turns a recorded OTel-GenAI trace export into that model.
//
// ForkSpan reads OTel-GenAI spans (OTLP-JSON export). Per the OTel-GenAI
// semantic conventions, the GenAI role of a span (LLM / Tool / Agent) is
// derived from the span name + the gen_ai.* attributes — it is NEVER a
// SpanKind value. SpanKind stays one of the OTLP generic kinds
// (INTERNAL | SERVER | CLIENT | PRODUCER | CONSUMER); GenAI classification
// lives entirely in the gen_ai.* attributes below.
package ingest

import (
	"encoding/json"
	"time"
)

// SpanKind is the OTLP generic span kind (NOT a GenAI role).
type SpanKind int

const (
	SpanKindUnspecified SpanKind = iota
	SpanKindInternal
	SpanKindServer
	SpanKindClient
	SpanKindProducer
	SpanKindConsumer
)

// String renders a SpanKind for display.
func (k SpanKind) String() string {
	switch k {
	case SpanKindInternal:
		return "INTERNAL"
	case SpanKindServer:
		return "SERVER"
	case SpanKindClient:
		return "CLIENT"
	case SpanKindProducer:
		return "PRODUCER"
	case SpanKindConsumer:
		return "CONSUMER"
	default:
		return "UNSPECIFIED"
	}
}

// MarshalJSON renders a SpanKind as the OTLP canonical string enum
// ("SPAN_KIND_INTERNAL" etc.) so the snapshot's reached_spans stay symmetric
// with the parser's string-enum input (spanKindFromString reads these). The
// TUI/diff display path keeps using String() (short form) unchanged.
func (k SpanKind) MarshalJSON() ([]byte, error) {
	var s string
	switch k {
	case SpanKindInternal:
		s = "SPAN_KIND_INTERNAL"
	case SpanKindServer:
		s = "SPAN_KIND_SERVER"
	case SpanKindClient:
		s = "SPAN_KIND_CLIENT"
	case SpanKindProducer:
		s = "SPAN_KIND_PRODUCER"
	case SpanKindConsumer:
		s = "SPAN_KIND_CONSUMER"
	default:
		s = "SPAN_KIND_UNSPECIFIED"
	}
	return json.Marshal(s)
}

// StatusCode mirrors the OTLP status code.
type StatusCode int

const (
	StatusUnset StatusCode = iota
	StatusOK
	StatusError
)

// MarshalJSON renders a StatusCode as the OTLP canonical string enum
// ("STATUS_CODE_OK" etc.) so the snapshot's reached_spans stay symmetric with
// the parser's string-enum input (statusCodeFromString reads these).
func (c StatusCode) MarshalJSON() ([]byte, error) {
	var s string
	switch c {
	case StatusOK:
		s = "STATUS_CODE_OK"
	case StatusError:
		s = "STATUS_CODE_ERROR"
	default:
		s = "STATUS_CODE_UNSET"
	}
	return json.Marshal(s)
}

// Status is ForkSpan's run-level status, including the synthetic BLOCKED
// value used by counterfactual mutations (m2). For m1 it carries OK/ERROR
// read straight from the recorded OTLP status.
type Status struct {
	Code    StatusCode `json:"code"`
	Message string     `json:"message"`
}

// String renders a Status for display.
func (s Status) String() string {
	switch s.Code {
	case StatusOK:
		return "OK"
	case StatusError:
		return "ERROR"
	default:
		return "UNSET"
	}
}

// KeyValue is a simplification of an OTLP AnyValue attribute pair. Values are
// kept as their native Go representation (string / int64 / float64 / bool /
// []byte / []any / map[string]any). The exported Value field is opaque by
// design: counterfactual projection copies it verbatim.
type KeyValue struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// ValueString returns a string view of an attribute value for display.
func (kv KeyValue) ValueString() string {
	switch v := kv.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

// GenAIRole classifies a span by its OTel-GenAI operation.
type GenAIRole string

const (
	RoleAgent   GenAIRole = "Agent"
	RoleLLM     GenAIRole = "LLM"
	RoleTool    GenAIRole = "Tool"
	RoleUnknown GenAIRole = ""
)

// Span is ForkSpan's working span model. It mirrors the OTLP-GenAI span after
// projection: the GenAI role is derived (never a SpanKind), the tool name is
// lifted out of gen_ai.tool.name, and Input/Output are the recorded payloads
// (gen_ai.request / gen_ai.response / gen_ai.tool.input / gen_ai.tool.output).
type Span struct {
	SpanID   string     `json:"span_id"`
	ParentID string     `json:"parent_id"`
	TraceID  string     `json:"trace_id"`
	Kind     SpanKind   `json:"kind"`
	Name     string     `json:"name"`
	ToolName string     `json:"tool_name"`
	Role     GenAIRole  `json:"role"`
	Attrs    []KeyValue `json:"attrs"`
	Input    []byte     `json:"input"`
	Output   []byte     `json:"output"`
	Start    time.Time  `json:"start"`
	End      time.Time  `json:"end"`
	Status   Status     `json:"status"`

	// Intrusion is true when the recorded trace marks this span as the
	// intrusion point (the forkspan.intrusion attribute). The operator may
	// also mark a span live in the TUI; that selection is tracked by the TUI,
	// not copied back here.
	Intrusion bool `json:"intrusion"`
}

// IsToolCall reports whether the span is a GenAI tool-call span (Role==Tool).
// Tool-call spans are the unit of the counterfactual subgraph.
func (s Span) IsToolCall() bool { return s.Role == RoleTool }

// Attr returns the first attribute matching key, or ("", nil).
func (s Span) Attr(key string) (KeyValue, bool) {
	for _, a := range s.Attrs {
		if a.Key == key {
			return a, true
		}
	}
	return KeyValue{}, false
}

// AttrString returns the string form of the first attribute matching key.
func (s Span) AttrString(key string) string {
	if a, ok := s.Attr(key); ok {
		return a.ValueString()
	}
	return ""
}

// Duration returns the span's recorded wall-clock duration.
func (s Span) Duration() time.Duration {
	if s.End.IsZero() || s.Start.IsZero() {
		return 0
	}
	return s.End.Sub(s.Start)
}
