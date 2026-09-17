package streaming_models

import (
	"encoding/json"
	"testing"
)

// compile-time proof the value type satisfies the interface.
var _ StreamEvent = AuthActivityAuditEvent{}

func TestAuthActivityAuditEventEventType(t *testing.T) {
	t.Parallel()
	if got := (AuthActivityAuditEvent{}).EventType(); got != "AuthActivityAuditEvent" {
		t.Fatalf("EventType() = %q, want %q", got, "AuthActivityAuditEvent")
	}
}

func TestAuthActivityAuditEventKnownFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, e AuthActivityAuditEvent)
	}{
		{
			name:  "attributes populated",
			input: `{"OperationName":"userAuthenticate","Attributes":[{"Key":"foo","ValueString":"bar"}]}`,
			check: func(t *testing.T, e AuthActivityAuditEvent) {
				if e.OperationName == nil || *e.OperationName != "userAuthenticate" {
					t.Fatalf("OperationName = %v, want userAuthenticate", e.OperationName)
				}
				if e.Attributes == nil || len(*e.Attributes) != 1 {
					t.Fatalf("Attributes len = %v, want 1", e.Attributes)
				}
				if (*e.Attributes)[0].Key != "foo" || (*e.Attributes)[0].Value != "bar" {
					t.Fatalf("Attributes[0] = %+v", (*e.Attributes)[0])
				}
			},
		},
		{
			name:  "empty object",
			input: `{}`,
			check: func(t *testing.T, e AuthActivityAuditEvent) {
				if e.OperationName != nil || e.Attributes != nil {
					t.Fatalf("expected nil fields, got %+v", e)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var e AuthActivityAuditEvent
			if err := json.Unmarshal([]byte(tc.input), &e); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			tc.check(t, e)
		})
	}
}

func TestAuthActivityAuditEventExtra(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		wantExtra  []string // keys expected in Extra
		wantAbsent []string // keys that must NOT be in Extra
	}{
		{
			name:       "unmodeled key captured",
			input:      `{"OperationName":"x","NewApiField":"v"}`,
			wantExtra:  []string{"NewApiField"},
			wantAbsent: []string{"OperationName"},
		},
		{
			name:      "all known keys leave Extra nil",
			input:     `{"OperationName":"x"}`,
			wantExtra: nil,
		},
		{
			name:      "empty object leaves Extra nil",
			input:     `{}`,
			wantExtra: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var e AuthActivityAuditEvent
			if err := json.Unmarshal([]byte(tc.input), &e); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if tc.wantExtra == nil && e.Extra != nil {
				t.Fatalf("Extra = %v, want nil", e.Extra)
			}
			for _, k := range tc.wantExtra {
				if _, ok := e.Extra[k]; !ok {
					t.Fatalf("Extra missing key %q; got %v", k, e.Extra)
				}
			}
			for _, k := range tc.wantAbsent {
				if _, ok := e.Extra[k]; ok {
					t.Fatalf("Extra should not contain known key %q", k)
				}
			}
		})
	}
}

func TestAuthActivityAuditEventExtraError(t *testing.T) {
	t.Parallel()
	var e AuthActivityAuditEvent
	if err := json.Unmarshal([]byte(`not json`), &e); err == nil {
		t.Fatal("expected error for invalid json, got nil")
	}
}

func TestAuthActivityAuditEventExtraCaseVariant(t *testing.T) {
	t.Parallel()
	// encoding/json matches field names case-insensitively, so a case variant
	// of a known key populates the typed field. It must not also linger in Extra.
	var e AuthActivityAuditEvent
	if err := json.Unmarshal([]byte(`{"operationname":"x"}`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.OperationName == nil || *e.OperationName != "x" {
		t.Fatalf("OperationName = %v, want x", e.OperationName)
	}
	if _, ok := e.Extra["operationname"]; ok {
		t.Fatalf("Extra should not contain case-variant of known key, got %v", e.Extra)
	}
}

func TestAuthActivityAuditEventMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	var e AuthActivityAuditEvent
	if err := json.Unmarshal([]byte(`{"OperationName":"x","NewApiField":"keepme"}`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var round map[string]json.RawMessage
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if _, ok := round["OperationName"]; !ok {
		t.Fatalf("marshal dropped typed field, got %s", out)
	}
	if _, ok := round["NewApiField"]; !ok {
		t.Fatalf("marshal dropped preserved Extra key, got %s", out)
	}
}

func TestAuthActivityAuditEventMarshalNoExtra(t *testing.T) {
	t.Parallel()
	op := "x"
	e := AuthActivityAuditEvent{OperationName: &op}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"OperationName":"x"}`; string(out) != want {
		t.Fatalf("Marshal = %s, want %s", out, want)
	}
}
