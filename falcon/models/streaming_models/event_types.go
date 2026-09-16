package streaming_models

import (
	"encoding/json"
	"fmt"
)

// StreamEvent is implemented by every typed streaming event payload. The
// returned value matches the metadata.eventType discriminator on the wire.
type StreamEvent interface {
	EventType() string
}

// AuthActivityAuditEvent is the typed payload for AuthActivityAuditEvent
// streaming events. Unmodeled wire fields are preserved in Extra.
type AuthActivityAuditEvent struct {
	OperationName  *string           `json:"OperationName,omitempty"`
	ServiceName    *string           `json:"ServiceName,omitempty"`
	UserID         *string           `json:"UserId,omitempty"`
	UserIP         *string           `json:"UserIp,omitempty"`
	Success        *bool             `json:"Success,omitempty"`
	UTCTimestamp   *uint64           `json:"UTCTimestamp,omitempty"`
	AuditKeyValues *[]AuditKeyValues `json:"AuditKeyValues,omitempty"`
	Attributes     *[]AuditKeyValues `json:"Attributes,omitempty"`

	// Extra holds any wire fields not represented by a typed field above,
	// so newly-added API fields survive a decode instead of being dropped.
	Extra map[string]json.RawMessage `json:"-"`
}

// EventType returns the metadata.eventType discriminator for this event.
// It uses a value receiver so the value type satisfies StreamEvent and can
// be inspected by As before any pointer is taken.
func (AuthActivityAuditEvent) EventType() string {
	return "AuthActivityAuditEvent"
}

// knownAuthActivityAuditEventKeys lists the wire keys already mapped to typed
// fields on AuthActivityAuditEvent. Keys not in this set are routed to Extra.
// Keep it in sync with the json tags above when adding or removing a field.
var knownAuthActivityAuditEventKeys = []string{
	"OperationName",
	"ServiceName",
	"UserId",
	"UserIp",
	"Success",
	"UTCTimestamp",
	"AuditKeyValues",
	"Attributes",
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
	for _, k := range knownAuthActivityAuditEventKeys {
		delete(raw, k)
	}
	if len(raw) > 0 {
		e.Extra = raw
	}
	return nil
}
