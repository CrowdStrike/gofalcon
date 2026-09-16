package streaming_models

import (
	"encoding/json"
	"fmt"
)

// As decodes an EventItem's retained raw payload into the typed streaming
// event T. It returns an error when the item's metadata.eventType does not
// match T's discriminator, and wraps any JSON decode failure. Because Go has
// no generic methods, As is a package-level function rather than a method.
func As[T StreamEvent](item *EventItem) (*T, error) {
	var t T
	if item.Metadata.EventType != t.EventType() {
		return nil, fmt.Errorf("stream: event %q is not %q", item.Metadata.EventType, t.EventType())
	}
	if err := json.Unmarshal(item.RawMessage, &t); err != nil {
		return nil, fmt.Errorf("stream: decode %s: %w", t.EventType(), err)
	}
	return &t, nil
}
