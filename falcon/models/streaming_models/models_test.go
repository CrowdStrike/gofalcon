package streaming_models

import (
	"encoding/json"
	"errors"
	"fmt"
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
		// wantAdditional expects Attributes not to fit, so that it is left
		// empty and kept in Event.Additional instead.
		wantAdditional bool
	}{
		{
			// The audit events always send an object, so a list of
			// Key/ValueString pairs does not fit.
			name:           "list of key/value pairs does not fit",
			attributes:     `[{"Key":"k","ValueString":"v"}]`,
			wantAdditional: true,
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
			name:           "unsupported form does not fit",
			attributes:     `"text"`,
			wantAdditional: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := `{"metadata":{"eventType":"UserActivityAuditEvent"},"event":{"OperationName":"x","Attributes":` + tc.attributes + `}}`
			var item EventItem
			if err := json.Unmarshal([]byte(input), &item); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if item.Event.OperationName == nil || *item.Event.OperationName != "x" {
				t.Fatalf("OperationName = %v, want x", item.Event.OperationName)
			}
			if !reflect.DeepEqual(item.Event.Attributes, tc.want) {
				t.Fatalf("Attributes = %#v, want %#v", item.Event.Attributes, tc.want)
			}
			var wantAdditional map[string]json.RawMessage
			if tc.wantAdditional {
				wantAdditional = map[string]json.RawMessage{"Attributes": json.RawMessage(tc.attributes)}
			}
			if !reflect.DeepEqual(item.Event.Additional, wantAdditional) {
				t.Fatalf("Additional = %s, want %s", item.Event.Additional, wantAdditional)
			}
		})
	}
}

// Every field of an event is kept: in its typed field when it has one and its
// value fits, and in Additional otherwise, so that no event is lost because
// the model does not know a field or the type of one has changed.
func TestEventItemAdditional(t *testing.T) {
	t.Parallel()

	str := func(s string) *string { return &s }
	tests := []struct {
		name           string
		event          string
		want           Event
		wantAdditional map[string]string
	}{
		{
			name:           "fields that Event does not declare",
			event:          `{"OperationName":"x","Action":"create_user","Extensions":{"k":"v"},"ActorType":1}`,
			want:           Event{OperationName: str("x")},
			wantAdditional: map[string]string{"Action": `"create_user"`, "Extensions": `{"k":"v"}`, "ActorType": `1`},
		},
		{
			name:  "every field typed leaves Additional nil",
			event: `{"OperationName":"x","UserId":"u"}`,
			want:  Event{OperationName: str("x"), UserId: str("u")},
		},
		{
			name:           "value that does not fit its typed field",
			event:          `{"OperationName":"x","UTCTimestamp":"soon"}`,
			want:           Event{OperationName: str("x")},
			wantAdditional: map[string]string{"UTCTimestamp": `"soon"`},
		},
		{
			name:           "value that the field's own UnmarshalJSON rejects",
			event:          `{"ProcessId":"not a number"}`,
			wantAdditional: map[string]string{"ProcessId": `"not a number"`},
		},
		{
			// encoding/json fills what it can of a slice before it fails, so
			// the typed field must be emptied again.
			name:           "value that only partly fits leaves the typed field empty",
			event:          `{"NetworkAccesses":[{"LocalPort":1},{"LocalPort":"x"}]}`,
			wantAdditional: map[string]string{"NetworkAccesses": `[{"LocalPort":1},{"LocalPort":"x"}]`},
		},
		{
			// The audit events of ScheduledReportNotificationEvent send UserID,
			// and EppDetectionSummaryEvent sends GrandParentCommandLine.
			name:  "names that differ from the typed field only in case",
			event: `{"UserID":"u","GrandParentCommandLine":"c"}`,
			want:  Event{UserId: str("u"), GrandparentCommandLine: str("c")},
		},
		{
			// USERID sorts before UserId, so only the exact match decides.
			name:           "exact name takes the typed field before a case variant",
			event:          `{"USERID":"variant","UserId":"exact"}`,
			want:           Event{UserId: str("exact")},
			wantAdditional: map[string]string{"USERID": `"variant"`},
		},
		{
			name:           "case variant takes the typed field when the exact name does not fit",
			event:          `{"UserId":1,"userid":"variant"}`,
			want:           Event{UserId: str("variant")},
			wantAdditional: map[string]string{"UserId": `1`},
		},
		{
			name:  "null value leaves the typed field empty",
			event: `{"UserId":null}`,
		},
		{name: "empty event", event: `{}`},
		{name: "null event", event: `null`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := `{"metadata":{"offset":7,"eventType":"T"},"event":` + tc.event + `}`
			var item EventItem
			if err := json.Unmarshal([]byte(input), &item); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if want := (Metadata{Offset: 7, EventType: "T"}); item.Metadata != want {
				t.Fatalf("Metadata = %+v, want %+v", item.Metadata, want)
			}
			var wantAdditional map[string]json.RawMessage
			for name, value := range tc.wantAdditional {
				if wantAdditional == nil {
					wantAdditional = map[string]json.RawMessage{}
				}
				wantAdditional[name] = json.RawMessage(value)
			}
			if !reflect.DeepEqual(item.Event.Additional, wantAdditional) {
				t.Fatalf("Additional = %s, want %s", item.Event.Additional, wantAdditional)
			}
			item.Event.Additional = nil
			if !reflect.DeepEqual(item.Event, tc.want) {
				got, _ := json.Marshal(item.Event)
				want, _ := json.Marshal(tc.want)
				t.Fatalf("Event = %s, want %s", got, want)
			}
		})
	}
}

// When several names of an event match one typed field, the same one takes it
// on every decode, whatever the order of the map they are read from.
func TestEventItemCaseVariantStable(t *testing.T) {
	t.Parallel()

	input := []byte(`{"event":{"userid":"lower","USERID":"upper","UserID":"mixed"}}`)
	wantAdditional := map[string]json.RawMessage{"userid": json.RawMessage(`"lower"`), "UserID": json.RawMessage(`"mixed"`)}
	for range 50 {
		var item EventItem
		if err := json.Unmarshal(input, &item); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if item.Event.UserId == nil || *item.Event.UserId != "upper" {
			t.Fatalf("UserId = %v, want upper on every decode", item.Event.UserId)
		}
		if !reflect.DeepEqual(item.Event.Additional, wantAdditional) {
			t.Fatalf("Additional = %s, want %s", item.Event.Additional, wantAdditional)
		}
	}
}

// A message without an event decodes with an empty Event.
func TestEventItemWithoutEvent(t *testing.T) {
	t.Parallel()

	var item EventItem
	if err := json.Unmarshal([]byte(`{"metadata":{"offset":7}}`), &item); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if item.Metadata.Offset != 7 || !reflect.DeepEqual(item.Event, Event{}) {
		t.Fatalf("item = %s, want offset 7 and an empty Event", describeItem(item))
	}
}

// Decoding into an item that holds an earlier message replaces all of it, so
// that nothing of the earlier message is left behind. A JSON null, by
// convention, leaves the item as it was.
func TestEventItemDecodeIntoUsedItem(t *testing.T) {
	t.Parallel()

	name := "x"
	earlier := EventItem{
		Metadata:   Metadata{CID: "c", Offset: 1},
		Event:      Event{UserId: &name, Additional: map[string]json.RawMessage{"Action": json.RawMessage(`"a"`)}},
		RawMessage: json.RawMessage(`{}`),
	}
	tests := []struct {
		name  string
		input string
		want  EventItem
	}{
		{
			name:  "message replaces the whole item",
			input: `{"metadata":{"offset":2},"event":{"OperationName":"x"}}`,
			want:  EventItem{Metadata: Metadata{Offset: 2}, Event: Event{OperationName: &name}},
		},
		{name: "null leaves the item as it was", input: `null`, want: earlier},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			item := earlier
			if err := json.Unmarshal([]byte(tc.input), &item); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !reflect.DeepEqual(item, tc.want) {
				t.Fatalf("item = %s, want %s", describeItem(item), describeItem(tc.want))
			}
		})
	}
}

// describeItem shows the values of an item rather than the addresses of its
// typed fields.
func describeItem(item EventItem) string {
	event, _ := json.Marshal(item.Event)
	return fmt.Sprintf("{Metadata: %+v, Event: %s, Additional: %s, RawMessage: %s}", item.Metadata, event, item.Event.Additional, item.RawMessage)
}

// jsonFieldIndex finds a typed field by the name encoding/json would give it,
// and skips the fields that encoding/json skips.
func TestJSONFieldIndex(t *testing.T) {
	t.Parallel()

	type fields struct {
		Tagged   string `json:"tagged,omitempty"`
		Untagged string
		Skipped  string `json:"-"`
		private  string //nolint:unused // encoding/json skips unexported fields.
	}
	declared, folded := jsonFieldIndex(reflect.TypeFor[fields]())
	if want := map[string]int{"tagged": 0, "Untagged": 1}; !reflect.DeepEqual(declared, want) {
		t.Fatalf("declared = %v, want %v", declared, want)
	}
	if want := map[string]int{"tagged": 0, "untagged": 1}; !reflect.DeepEqual(folded, want) {
		t.Fatalf("folded = %v, want %v", folded, want)
	}
}

// Only a message that is not an event fails to decode: an event that is not a
// JSON object, or metadata that does not fit, which every event type shares.
func TestEventItemDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "event that is not an object", input: `{"metadata":{"offset":7},"event":"text"}`},
		{name: "metadata that does not fit", input: `{"metadata":{"offset":"seven"},"event":{}}`},
		{name: "message that is not an object", input: `[1]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var item EventItem
			err := json.Unmarshal([]byte(tc.input), &item)
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &typeErr) {
				t.Fatalf("Unmarshal error = %v, item %+v, want a *json.UnmarshalTypeError", err, item)
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

// Additional is left out when an Event is marshaled, so that a decoded event
// marshals with its typed fields only.
func TestEventMarshalLeavesOutAdditional(t *testing.T) {
	t.Parallel()

	var item EventItem
	if err := json.Unmarshal([]byte(`{"event":{"OperationName":"x","Action":"a"}}`), &item); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(item.Event)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"OperationName":"x"}`; string(out) != want {
		t.Fatalf("Marshal = %s, want %s", out, want)
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

// A consumer type that embeds Event must still decode and encode its own
// fields, so Event itself must not implement json.Unmarshaler or
// json.Marshaler.
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
	out, err := json.Marshal(enriched)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"OperationName":"x","Attributes":{"k":"v"},"tenant":"acme"}`; string(out) != want {
		t.Fatalf("Marshal = %s, want %s", out, want)
	}
}

// A consumer type that embeds EventItem must still encode its own fields, so
// EventItem must not implement json.Marshaler. Decoding one does not fill
// them, since EventItem implements json.Unmarshaler.
func TestEventItemEmbeddedMarshalKeepsOuterFields(t *testing.T) {
	t.Parallel()

	var enriched struct {
		EventItem
		Tenant string `json:"tenant"`
	}
	if err := json.Unmarshal([]byte(`{"metadata":{"offset":7},"event":{"OperationName":"x","Action":"a"}}`), &enriched.EventItem); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	enriched.Tenant = "acme"
	out, err := json.Marshal(enriched)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var marshaled struct {
		Event  map[string]json.RawMessage `json:"event"`
		Tenant string                     `json:"tenant"`
	}
	if err := json.Unmarshal(out, &marshaled); err != nil {
		t.Fatalf("Unmarshal of the marshaled item: %v", err)
	}
	if marshaled.Tenant != "acme" || string(marshaled.Event["OperationName"]) != `"x"` {
		t.Fatalf("Marshal = %s, want tenant acme and OperationName x", out)
	}
}
