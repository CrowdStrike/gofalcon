package streaming_models

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// StreamEvent is implemented by every typed streaming event payload. The
// returned value matches the metadata.eventType discriminator on the wire.
type StreamEvent interface {
	EventType() string
}

// AuthActivityAuditEvent is the typed payload for AuthActivityAuditEvent
// streaming events. Wire fields not represented by a typed field are preserved
// in Extra and are re-emitted on marshal, so a decode/encode round-trip does
// not drop newly-added API fields.
type AuthActivityAuditEvent struct {
	OperationName  *string           `json:"OperationName,omitempty"`
	ServiceName    *string           `json:"ServiceName,omitempty"`
	UserID         *string           `json:"UserId,omitempty"`
	UserIP         *string           `json:"UserIp,omitempty"`
	Success        *bool             `json:"Success,omitempty"`
	UTCTimestamp   *uint64           `json:"UTCTimestamp,omitempty"`
	AuditKeyValues *[]AuditKeyValues `json:"AuditKeyValues,omitempty"`
	Attributes     *[]AuditKeyValues `json:"Attributes,omitempty"`

	// Extra holds any wire fields not represented by a typed field above, so
	// newly-added API fields survive a decode and are re-emitted on marshal.
	Extra map[string]json.RawMessage `json:"-"`
}

// EventType returns the metadata.eventType discriminator for this event.
// It uses a value receiver so the value type satisfies StreamEvent and can
// be inspected by As before any pointer is taken.
func (AuthActivityAuditEvent) EventType() string {
	return "AuthActivityAuditEvent"
}

// authActivityAuditEventFields is the set of lowercased json field names mapped
// to typed fields on AuthActivityAuditEvent. Deriving it from the struct tags
// keeps it in step with the fields automatically, and lowercasing mirrors the
// case-insensitive matching encoding/json uses so a case variant of a known key
// is not both decoded into its field and duplicated into Extra.
var authActivityAuditEventFields = jsonFieldSet(reflect.TypeFor[AuthActivityAuditEvent]())

// jsonFieldSet returns the lowercased json field names declared on struct type
// t, skipping fields with no name or a "-" tag.
func jsonFieldSet(t reflect.Type) map[string]struct{} {
	set := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		set[strings.ToLower(name)] = struct{}{}
	}
	return set
}

// UnmarshalJSON decodes the typed fields and preserves any remaining wire
// fields in Extra so unmodeled API additions are not silently dropped.
func (e *AuthActivityAuditEvent) UnmarshalJSON(data []byte) error {
	type alias AuthActivityAuditEvent
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("decode AuthActivityAuditEvent: %w", err)
	}
	*e = AuthActivityAuditEvent(a)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode AuthActivityAuditEvent extra: %w", err)
	}
	for k := range raw {
		if _, known := authActivityAuditEventFields[strings.ToLower(k)]; known {
			delete(raw, k)
		}
	}
	if len(raw) > 0 {
		e.Extra = raw
	}
	return nil
}

// MarshalJSON emits the typed fields and merges the preserved Extra fields back
// in, so a value decoded from the wire re-marshals without losing unmodeled
// keys. Typed fields take precedence over any same-named Extra entry.
func (e AuthActivityAuditEvent) MarshalJSON() ([]byte, error) {
	type alias AuthActivityAuditEvent
	base, err := json.Marshal(alias(e))
	if err != nil {
		return nil, fmt.Errorf("encode AuthActivityAuditEvent: %w", err)
	}
	if len(e.Extra) == 0 {
		return base, nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, fmt.Errorf("encode AuthActivityAuditEvent: %w", err)
	}
	for k, v := range e.Extra {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	return json.Marshal(merged)
}
