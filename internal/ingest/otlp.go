package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	cmn "go.opentelemetry.io/proto/otlp/common/v1"
	otlp "go.opentelemetry.io/proto/otlp/trace/v1"
)

// Tree is a span tree: a flat span slice plus an index of children keyed by
// ParentID. ForkSpan's m1 navigator renders this tree.
type Tree struct {
	Spans    []Span
	byID     map[string]*Span
	children map[string][]string // parentID -> child IDs in start order
}

// LoadFile reads an OTLP-JSON export from path and returns the span tree.
// The export must be a canonical OTLP TracesData envelope
// ({"resourceSpans": [...]}).
func LoadFile(path string) (*Tree, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trace %q: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes parses an OTLP-JSON byte slice into a span tree. The OTLP/JSON
// wire format hex-encodes traceId/spanId and string-encodes the uint64
// unixNano timestamps (per the OTLP-JSON spec), so ForkSpan parses the
// envelope directly rather than via protojson (which would base64-decode the
// hex IDs).
func LoadBytes(data []byte) (*Tree, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty trace input")
	}
	trimmed := data
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\n' || trimmed[0] == '\r' || trimmed[0] == '\t') {
		trimmed = trimmed[1:]
	}
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty trace input")
	}

	var env otlpEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse OTLP-JSON: %w", err)
	}
	return NewTree(convertEnvelope(env)), nil
}

// NewTree builds a span tree from a flat span slice, indexing by ID and
// grouping children by ParentID in start-time order.
func NewTree(spans []Span) *Tree {
	t := &Tree{
		Spans:    spans,
		byID:     make(map[string]*Span, len(spans)),
		children: make(map[string][]string, len(spans)),
	}
	for i := range spans {
		t.byID[spans[i].SpanID] = &spans[i]
	}
	ordered := make([]Span, len(spans))
	copy(ordered, spans)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Start.Before(ordered[j].Start)
	})
	for i := range ordered {
		pid := ordered[i].ParentID
		t.children[pid] = append(t.children[pid], ordered[i].SpanID)
	}
	return t
}

// Get returns the span with id, or nil.
func (t *Tree) Get(id string) *Span { return t.byID[id] }

// Children returns the child span IDs of parentID in start order.
func (t *Tree) Children(parentID string) []string { return t.children[parentID] }

// Roots returns root span IDs: spans whose ParentID is empty.
func (t *Tree) Roots() []string {
	seen := map[string]bool{}
	var roots []string
	for _, s := range t.Spans {
		if s.ParentID == "" && !seen[s.SpanID] {
			roots = append(roots, s.SpanID)
			seen[s.SpanID] = true
		}
	}
	sort.SliceStable(roots, func(i, j int) bool {
		a, b := t.byID[roots[i]], t.byID[roots[j]]
		return a.Start.Before(b.Start)
	})
	return roots
}

// ToolCalls returns every tool-call span (Role==Tool) in start order.
func (t *Tree) ToolCalls() []Span {
	var out []Span
	for _, s := range t.Spans {
		if s.IsToolCall() {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// IntrusionSpan returns the span marked forkspan.intrusion=true in the
// recorded trace, or "" if none is marked.
func (t *Tree) IntrusionSpan() string {
	for _, s := range t.Spans {
		if a, ok := s.Attr("forkspan.intrusion"); ok {
			if b, _ := a.Value.(bool); b {
				return s.SpanID
			}
		}
	}
	return ""
}

// ---- OTLP/JSON wire-format structs (hex IDs, string unixNano) ----

type otlpEnvelope struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource  *otlpResource   `json:"resource,omitempty"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeSpans struct {
	Scope *otlpScope `json:"scope,omitempty"`
	Spans []otlpSpanJSON `json:"spans"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpSpanJSON struct {
	TraceID            string         `json:"traceId"`
	SpanID             string         `json:"spanId"`
	ParentSpanID       string         `json:"parentSpanId"`
	Name               string         `json:"name"`
	Kind               string         `json:"kind"`
	StartTimeUnixNano  string         `json:"startTimeUnixNano"`
	EndTimeUnixNano    string         `json:"endTimeUnixNano"`
	Attributes         []otlpKeyValue  `json:"attributes"`
	Status             *otlpStatusJSON `json:"status"`
}

type otlpStatusJSON struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type otlpKeyValue struct {
	Key   string        `json:"key"`
	Value otlpAnyJSON   `json:"value"`
}

// otlpAnyJSON mirrors the OTLP AnyValue oneof. proto3 JSON encodes int64 as a
// string and bytes as base64; the latter is unused by GenAI semconv.
type otlpAnyJSON struct {
	StringValue *string         `json:"stringValue,omitempty"`
	BoolValue   *bool           `json:"boolValue,omitempty"`
	IntValue    *json.Number    `json:"intValue,omitempty"`
	DoubleValue *float64        `json:"doubleValue,omitempty"`
	ArrayValue  *otlpArrayValue `json:"arrayValue,omitempty"`
	KvlistValue *otlpKvlist     `json:"kvlistValue,omitempty"`
}

type otlpArrayValue struct {
	Values []otlpAnyJSON `json:"values"`
}

type otlpKvlist struct {
	Values []otlpKeyValue `json:"values"`
}

func convertEnvelope(env otlpEnvelope) []Span {
	var out []Span
	for _, rs := range env.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				out = append(out, convertSpanJSON(sp))
			}
		}
	}
	return out
}

func convertSpanJSON(sp otlpSpanJSON) Span {
	s := Span{
		SpanID:   sp.SpanID,
		ParentID: sp.ParentSpanID,
		TraceID:  sp.TraceID,
		Kind:     spanKindFromString(sp.Kind),
		Name:     sp.Name,
		Start:    parseNanoTime(sp.StartTimeUnixNano),
		End:      parseNanoTime(sp.EndTimeUnixNano),
	}
	for _, kv := range sp.Attributes {
		s.Attrs = append(s.Attrs, KeyValue{Key: kv.Key, Value: anyJSONValue(kv.Value)})
	}

	op := s.AttrString("gen_ai.operation.name")
	switch op {
	case "chat":
		s.Role = RoleLLM
	case "execute_tool":
		s.Role = RoleTool
		s.ToolName = s.AttrString("gen_ai.tool.name")
	case "invoke_agent":
		s.Role = RoleAgent
	default:
		s.Role = inferRole(s.Name)
	}

	s.Input = []byte(s.AttrString("gen_ai.request.content"))
	if len(s.Input) == 0 {
		s.Input = []byte(s.AttrString("gen_ai.tool.input"))
	}
	s.Output = []byte(s.AttrString("gen_ai.response.content"))
	if len(s.Output) == 0 {
		s.Output = []byte(s.AttrString("gen_ai.tool.output"))
	}

	if sp.Status != nil {
		s.Status = Status{
			Code:    statusCodeFromString(sp.Status.Code),
			Message: sp.Status.Message,
		}
	} else {
		s.Status = Status{Code: StatusUnset}
	}

	if a, ok := s.Attr("forkspan.intrusion"); ok {
		if b, _ := a.Value.(bool); b {
			s.Intrusion = true
		}
	}
	return s
}

func anyJSONValue(v otlpAnyJSON) any {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.BoolValue != nil:
		return *v.BoolValue
	case v.IntValue != nil:
		if i, err := v.IntValue.Int64(); err == nil {
			return i
		}
		return v.IntValue.String()
	case v.DoubleValue != nil:
		return *v.DoubleValue
	case v.ArrayValue != nil:
		var arr []any
		for _, e := range v.ArrayValue.Values {
			arr = append(arr, anyJSONValue(e))
		}
		return arr
	case v.KvlistValue != nil:
		m := map[string]any{}
		for _, kv := range v.KvlistValue.Values {
			m[kv.Key] = anyJSONValue(kv.Value)
		}
		return m
	}
	return nil
}

func spanKindFromString(k string) SpanKind {
	switch k {
	case "SPAN_KIND_INTERNAL":
		return SpanKindInternal
	case "SPAN_KIND_SERVER":
		return SpanKindServer
	case "SPAN_KIND_CLIENT":
		return SpanKindClient
	case "SPAN_KIND_PRODUCER":
		return SpanKindProducer
	case "SPAN_KIND_CONSUMER":
		return SpanKindConsumer
	}
	return SpanKindUnspecified
}

func statusCodeFromString(c string) StatusCode {
	switch c {
	case "STATUS_CODE_OK":
		return StatusOK
	case "STATUS_CODE_ERROR":
		return StatusError
	}
	return StatusUnset
}

func parseNanoTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, int64(n)).UTC()
}

// ---- proto interop (in-memory OTLP TracesData → ForkSpan spans) ----
//
// FromTracesData converts an in-memory OTLP TracesData (the type emitted by
// an OTLP gRPC/HTTP collector) into ForkSpan spans. Networked collection is
// out of scope for v0.1, but this converter is the interop seam a future
// collector would call; it also keeps the go.opentelemetry.io/proto/otlp
// types as a first-class model.
func FromTracesData(td *otlp.TracesData) []Span {
	var out []Span
	for _, rs := range td.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				out = append(out, convertSpanProto(sp))
			}
		}
	}
	return out
}

func convertSpanProto(sp *otlp.Span) Span {
	s := Span{
		SpanID:   hexEncode(sp.SpanId),
		ParentID: hexEncode(sp.ParentSpanId),
		TraceID:  hexEncode(sp.TraceId),
		Kind:     spanKindFromProto(sp.Kind),
		Name:     sp.Name,
		Start:    nanoToTime(sp.StartTimeUnixNano),
		End:      nanoToTime(sp.EndTimeUnixNano),
	}
	for _, kv := range sp.Attributes {
		s.Attrs = append(s.Attrs, KeyValue{Key: kv.Key, Value: anyValue(kv.Value)})
	}
	op := s.AttrString("gen_ai.operation.name")
	switch op {
	case "chat":
		s.Role = RoleLLM
	case "execute_tool":
		s.Role = RoleTool
		s.ToolName = s.AttrString("gen_ai.tool.name")
	case "invoke_agent":
		s.Role = RoleAgent
	default:
		s.Role = inferRole(s.Name)
	}
	s.Input = []byte(s.AttrString("gen_ai.request.content"))
	if len(s.Input) == 0 {
		s.Input = []byte(s.AttrString("gen_ai.tool.input"))
	}
	s.Output = []byte(s.AttrString("gen_ai.response.content"))
	if len(s.Output) == 0 {
		s.Output = []byte(s.AttrString("gen_ai.tool.output"))
	}
	if sp.Status != nil {
		s.Status = Status{Code: statusCodeFromProto(sp.Status.Code), Message: sp.Status.Message}
	} else {
		s.Status = Status{Code: StatusUnset}
	}
	if a, ok := s.Attr("forkspan.intrusion"); ok {
		if b, _ := a.Value.(bool); b {
			s.Intrusion = true
		}
	}
	return s
}

func attrString(kvs []*cmn.KeyValue, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			if v := anyValue(kv.Value); v != nil {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func spanKindFromProto(k otlp.Span_SpanKind) SpanKind {
	switch k {
	case otlp.Span_SPAN_KIND_INTERNAL:
		return SpanKindInternal
	case otlp.Span_SPAN_KIND_SERVER:
		return SpanKindServer
	case otlp.Span_SPAN_KIND_CLIENT:
		return SpanKindClient
	case otlp.Span_SPAN_KIND_PRODUCER:
		return SpanKindProducer
	case otlp.Span_SPAN_KIND_CONSUMER:
		return SpanKindConsumer
	}
	return SpanKindUnspecified
}

func statusCodeFromProto(c otlp.Status_StatusCode) StatusCode {
	switch c {
	case otlp.Status_STATUS_CODE_OK:
		return StatusOK
	case otlp.Status_STATUS_CODE_ERROR:
		return StatusError
	}
	return StatusUnset
}

func nanoToTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns)).UTC()
}

// anyValue projects an OTLP AnyValue oneof into a native Go value.
func anyValue(v *cmn.AnyValue) any {
	if v == nil {
		return nil
	}
	switch x := v.Value.(type) {
	case *cmn.AnyValue_StringValue:
		return x.StringValue
	case *cmn.AnyValue_BoolValue:
		return x.BoolValue
	case *cmn.AnyValue_IntValue:
		return x.IntValue
	case *cmn.AnyValue_DoubleValue:
		return x.DoubleValue
	case *cmn.AnyValue_BytesValue:
		return x.BytesValue
	case *cmn.AnyValue_ArrayValue:
		var arr []any
		for _, e := range x.ArrayValue.Values {
			arr = append(arr, anyValue(e))
		}
		return arr
	case *cmn.AnyValue_KvlistValue:
		m := map[string]any{}
		for _, kv := range x.KvlistValue.Values {
			m[kv.Key] = anyValue(kv.Value)
		}
		return m
	}
	return nil
}

// hexEncode lower-case hex-encodes an OTLP id field (which protojson decodes
// from the JSON hex string into a raw byte slice on the proto path).
func hexEncode(b []byte) string {
	const hexc = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexc[c>>4]
		out[i*2+1] = hexc[c&0x0f]
	}
	return string(out)
}

func inferRole(name string) GenAIRole {
	switch {
	case contains(name, "llm.chat"), contains(name, "llm"), contains(name, "chat"):
		return RoleLLM
	case contains(name, "tool.call"), contains(name, "tool"), contains(name, "execute_tool"):
		return RoleTool
	case contains(name, "agent.invoke"), contains(name, "agent"), contains(name, "invoke_agent"):
		return RoleAgent
	}
	return RoleUnknown
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
