package streaming_models

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestEventAttributes(t *testing.T) {
	t.Parallel()

	// The reporter's path reads item.Event directly, so the legacy Event must
	// expose Attributes in every form the audit events send it.
	tests := []struct {
		name       string
		attributes string
		want       AuditAttributes
		// wantTypeErr expects the decode to fail with a json.UnmarshalTypeError.
		wantTypeErr bool
	}{
		{
			// The audit events always send an object, so a list of
			// Key/ValueString pairs does not fit.
			name:        "list of key/value pairs is rejected",
			attributes:  `[{"Key":"k","ValueString":"v"}]`,
			wantTypeErr: true,
		},
		{
			// APIActivityAuditEvent, UserActivityAuditEvent and
			// AuthActivityAuditEvent send this form.
			name:       "object of string values",
			attributes: `{"user_ip":"j","trace_id":"i","request_method":"e"}`,
			want:       AuditAttributes{"user_ip": "j", "trace_id": "i", "request_method": "e"},
		},
		{
			name:       "object values that are not strings keep their JSON text",
			attributes: `{"count":3,"enabled":true,"nested":{"a":1}}`,
			want:       AuditAttributes{"count": "3", "enabled": "true", "nested": `{"a":1}`},
		},
		{
			name:       "escaped and unicode object values are unescaped",
			attributes: `{"path":"a\"b\\c","u":"caf\u00e9"}`,
			want:       AuditAttributes{"path": `a"b\c`, "u": "café"},
		},
		{
			name:       "null object value becomes an empty string",
			attributes: `{"k":null}`,
			want:       AuditAttributes{"k": ""},
		},
		{
			name:       "empty object",
			attributes: `{}`,
			want:       AuditAttributes{},
		},
		{
			name:       "null",
			attributes: `null`,
			want:       nil,
		},
		{
			name:        "unsupported form",
			attributes:  `"text"`,
			wantTypeErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := `{"metadata":{"eventType":"UserActivityAuditEvent"},"event":{"OperationName":"x","Attributes":` + tc.attributes + `}}`
			var item EventItem
			err := json.Unmarshal([]byte(input), &item)

			if tc.wantTypeErr {
				var typeErr *json.UnmarshalTypeError
				if !errors.As(err, &typeErr) {
					t.Fatalf("Unmarshal error = %v, want a *json.UnmarshalTypeError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if item.Event.OperationName == nil || *item.Event.OperationName != "x" {
				t.Fatalf("OperationName = %v, want x", item.Event.OperationName)
			}
			if !reflect.DeepEqual(item.Event.Attributes, tc.want) {
				t.Fatalf("Attributes = %#v, want %#v", item.Event.Attributes, tc.want)
			}
		})
	}
}

// Attributes marshal as an object of strings, and an empty one is left out.
func TestEventMarshalAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "object of strings", input: `{"Attributes":{"b":"2","a":"1"}}`, want: `{"Attributes":{"a":"1","b":"2"}}`},
		{
			name:  "values that are not strings come back as their JSON text",
			input: `{"Attributes":{"n":3,"z":null,"o":{"a":1}}}`,
			want:  `{"Attributes":{"n":"3","o":"{\"a\":1}","z":""}}`,
		},
		{name: "empty object", input: `{"Attributes":{}}`, want: `{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var e Event
			if err := json.Unmarshal([]byte(tc.input), &e); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			out, err := json.Marshal(e)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(out) != tc.want {
				t.Fatalf("Marshal = %s, want %s", out, tc.want)
			}
		})
	}
}

func TestEventWithoutAttributes(t *testing.T) {
	t.Parallel()

	var e Event
	if err := json.Unmarshal([]byte(`{"OperationName":"x"}`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Attributes != nil {
		t.Fatalf("Attributes = %#v, want nil", e.Attributes)
	}
}

// encoding/json hands null to an Unmarshaler that is not behind a pointer, and
// by convention that decode leaves the value as it was.
func TestAuditAttributesNullLeavesValue(t *testing.T) {
	t.Parallel()

	attributes := AuditAttributes{"k": "v"}
	if err := json.Unmarshal([]byte(`null`), &attributes); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if want := (AuditAttributes{"k": "v"}); !reflect.DeepEqual(attributes, want) {
		t.Fatalf("Attributes = %#v, want %#v", attributes, want)
	}
}

// A consumer type that embeds Event must still decode its own fields, so Event
// itself must not implement json.Unmarshaler.
func TestEventEmbeddedKeepsOuterFields(t *testing.T) {
	t.Parallel()

	var enriched struct {
		Event
		Tenant string `json:"tenant"`
	}
	input := `{"OperationName":"x","Attributes":{"k":"v"},"tenant":"acme"}`
	if err := json.Unmarshal([]byte(input), &enriched); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if enriched.Tenant != "acme" {
		t.Fatalf("Tenant = %q, want acme", enriched.Tenant)
	}
	if enriched.OperationName == nil || *enriched.OperationName != "x" {
		t.Fatalf("OperationName = %v, want x", enriched.OperationName)
	}
	if enriched.Attributes["k"] != "v" || len(enriched.Attributes) != 1 {
		t.Fatalf("Attributes = %#v, want k=v", enriched.Attributes)
	}
}
