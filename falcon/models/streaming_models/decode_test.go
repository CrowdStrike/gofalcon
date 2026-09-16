package streaming_models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAsHappyPath(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"OperationName":"userAuthenticate","Attributes":[{"Key":"k","ValueString":"v"}]}`)
	item := &EventItem{
		Metadata:   Metadata{EventType: "AuthActivityAuditEvent"},
		RawMessage: json.RawMessage(raw),
	}
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
}

func TestAsTypeMismatch(t *testing.T) {
	t.Parallel()
	item := &EventItem{
		Metadata:   Metadata{EventType: "DetectionSummaryEvent"},
		RawMessage: json.RawMessage(`{}`),
	}
	_, err := As[AuthActivityAuditEvent](item)
	if err == nil {
		t.Fatal("expected type-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "AuthActivityAuditEvent") ||
		!strings.Contains(err.Error(), "DetectionSummaryEvent") {
		t.Fatalf("error %q missing expected type names", err)
	}
}

func TestAsDecodeError(t *testing.T) {
	t.Parallel()
	item := &EventItem{
		Metadata:   Metadata{EventType: "AuthActivityAuditEvent"},
		RawMessage: json.RawMessage(`not json`),
	}
	_, err := As[AuthActivityAuditEvent](item)
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}
