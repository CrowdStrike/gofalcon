package streaming_models

import (
	"encoding/json"
	"strings"
	"testing"
)

// eventItemFromWire builds an EventItem the same way falcon/api_streaming.go
// does: decode the full envelope into the item and retain the whole envelope
// as RawMessage. Tests must exercise As against this shape, not a hand-built
// inner payload, because the envelope is the only level the transport emits.
func eventItemFromWire(t *testing.T, wire string) *EventItem {
	t.Helper()
	raw := json.RawMessage(wire)
	var item EventItem
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatalf("wire decode: %v", err)
	}
	item.RawMessage = raw
	return &item
}

func TestAsHappyPath(t *testing.T) {
	t.Parallel()
	item := eventItemFromWire(t, `{
		"metadata": {"eventType": "AuthActivityAuditEvent"},
		"event": {"OperationName": "userAuthenticate", "Attributes": [{"Key": "k", "ValueString": "v"}]}
	}`)
	got, err := As[AuthActivityAuditEvent](item)
	if err != nil {
		t.Fatalf("As: unexpected error %v", err)
	}
	if got.OperationName == nil || *got.OperationName != "userAuthenticate" {
		t.Fatalf("OperationName = %v", got.OperationName)
	}
	if got.Attributes == nil || len(*got.Attributes) != 1 {
		t.Fatalf("Attributes = %v", got.Attributes)
	}
	if (*got.Attributes)[0].Key != "k" || (*got.Attributes)[0].Value != "v" {
		t.Fatalf("Attributes[0] = %+v", (*got.Attributes)[0])
	}
	if got.Extra != nil {
		t.Fatalf("Extra = %v, want nil (envelope keys must not leak into Extra)", got.Extra)
	}
}

func TestAsTypeMismatch(t *testing.T) {
	t.Parallel()
	item := eventItemFromWire(t, `{"metadata": {"eventType": "DetectionSummaryEvent"}, "event": {}}`)
	_, err := As[AuthActivityAuditEvent](item)
	if err == nil {
		t.Fatal("expected type-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "AuthActivityAuditEvent") ||
		!strings.Contains(err.Error(), "DetectionSummaryEvent") {
		t.Fatalf("error %q missing expected type names", err)
	}
}

func TestAsEnvelopeDecodeError(t *testing.T) {
	t.Parallel()
	item := &EventItem{
		Metadata:   Metadata{EventType: "AuthActivityAuditEvent"},
		RawMessage: json.RawMessage(`not json`),
	}
	_, err := As[AuthActivityAuditEvent](item)
	if err == nil {
		t.Fatal("expected envelope decode error, got nil")
	}
}

func TestAsEventDecodeError(t *testing.T) {
	t.Parallel()
	// Valid envelope whose event payload is a string rather than an object.
	// Built directly rather than through the wire helper because the transport's
	// own parse would reject this shape first; As must still fail cleanly on it.
	item := &EventItem{
		Metadata:   Metadata{EventType: "AuthActivityAuditEvent"},
		RawMessage: json.RawMessage(`{"metadata": {"eventType": "AuthActivityAuditEvent"}, "event": "notanobject"}`),
	}
	_, err := As[AuthActivityAuditEvent](item)
	if err == nil {
		t.Fatal("expected event decode error, got nil")
	}
}

func TestAsPointerTypeReturnsError(t *testing.T) {
	t.Parallel()
	item := eventItemFromWire(t, `{"metadata": {"eventType": "AuthActivityAuditEvent"}, "event": {}}`)
	// The pointer type also satisfies StreamEvent; As must reject it with an
	// error rather than panicking on a nil-pointer method call.
	_, err := As[*AuthActivityAuditEvent](item)
	if err == nil {
		t.Fatal("expected error for pointer type instantiation, got nil")
	}
}
