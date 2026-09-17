package streaming_models

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// As decodes an EventItem's retained envelope into the typed streaming event T.
// EventItem.RawMessage holds the full wire envelope ({"metadata":...,"event":...}),
// so As extracts the inner event payload before decoding it into T. It returns an
// error when the item's metadata.eventType does not match T's discriminator, and
// wraps any JSON decode failure. Because Go has no generic methods, As is a
// package-level function rather than a method.
func As[T StreamEvent](item *EventItem) (*T, error) {
	var t T
	// The pointer type also satisfies StreamEvent, but its zero value is a nil
	// pointer whose EventType would panic. Reject it before any method call.
	if reflect.ValueOf(&t).Elem().Kind() == reflect.Pointer {
		return nil, fmt.Errorf("stream: As requires a value event type, not a pointer")
	}
	if item.Metadata.EventType != t.EventType() {
		return nil, fmt.Errorf("stream: event %q is not %q", item.Metadata.EventType, t.EventType())
	}

	var envelope struct {
		Event json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(item.RawMessage, &envelope); err != nil {
		return nil, fmt.Errorf("stream: decode %s envelope: %w", t.EventType(), err)
	}
	if err := json.Unmarshal(envelope.Event, &t); err != nil {
		return nil, fmt.Errorf("stream: decode %s: %w", t.EventType(), err)
	}
	return &t, nil
}
