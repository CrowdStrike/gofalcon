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
		want       *AuditAttributes
		// wantTypeErr expects the decode to fail with a json.UnmarshalTypeError.
		wantTypeErr bool
	}{
		{
			name:       "list of key/value pairs",
			attributes: `[{"Key":"k","ValueString":"v"}]`,
			want:       &AuditAttributes{{Key: "k", Value: "v"}},
		},
		{
			// APIActivityAuditEvent, UserActivityAuditEvent and
			// AuthActivityAuditEvent send this form. The keys arrive in reverse
			// order, and more than eight of them, so that map iteration order
			// cannot happen to match the sorted order.
			name: "object of string values comes back sorted by key",
			attributes: `{"user_ip":"j","trace_id":"i","sub_component_1":"h","status_code":"g","request_uri_length":"f",` +
				`"request_method":"e","request_host":"d","received_time":"c","produces":"b","elapsed_time":"a"}`,
			want: &AuditAttributes{
				{Key: "elapsed_time", Value: "a"},
				{Key: "produces", Value: "b"},
				{Key: "received_time", Value: "c"},
				{Key: "request_host", Value: "d"},
				{Key: "request_method", Value: "e"},
				{Key: "request_uri_length", Value: "f"},
				{Key: "status_code", Value: "g"},
				{Key: "sub_component_1", Value: "h"},
				{Key: "trace_id", Value: "i"},
				{Key: "user_ip", Value: "j"},
			},
		},
		{
			name:       "object values that are not strings keep their JSON text",
			attributes: `{"count":3,"enabled":true,"nested":{"a":1}}`,
			want:       &AuditAttributes{{Key: "count", Value: "3"}, {Key: "enabled", Value: "true"}, {Key: "nested", Value: `{"a":1}`}},
		},
		{
			name:       "null object value becomes an empty string",
			attributes: `{"k":null}`,
			want:       &AuditAttributes{{Key: "k", Value: ""}},
		},
		{
			name:       "empty object",
			attributes: `{}`,
			want:       &AuditAttributes{},
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
				t.Fatalf("Attributes = %+v, want %+v", deref(item.Event.Attributes), deref(tc.want))
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
		t.Fatalf("Attributes = %+v, want nil", *e.Attributes)
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
	if enriched.Attributes == nil || len(*enriched.Attributes) != 1 {
		t.Fatalf("Attributes = %+v, want one pair", deref(enriched.Attributes))
	}
}

func deref(attributes *AuditAttributes) any {
	if attributes == nil {
		return nil
	}
	return *attributes
}
