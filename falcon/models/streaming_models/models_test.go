package streaming_models

import (
	"encoding/json"
	"testing"
)

func TestEventAttributes(t *testing.T) {
	t.Parallel()
	// The reporter's path reads item.Event directly, so the legacy Event must
	// also expose Attributes for AuthActivityAuditEvent payloads.
	var e Event
	if err := json.Unmarshal([]byte(`{"OperationName":"x","Attributes":[{"Key":"k","ValueString":"v"}]}`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Attributes == nil || len(*e.Attributes) != 1 {
		t.Fatalf("Attributes = %v, want len 1", e.Attributes)
	}
	if (*e.Attributes)[0].Key != "k" || (*e.Attributes)[0].Value != "v" {
		t.Fatalf("Attributes[0] = %+v", (*e.Attributes)[0])
	}
}
