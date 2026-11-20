package streaming_models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// EventItem - The structure for parent model
type EventItem struct {
	Event      Event    `json:"event"    validate:"dive"`
	Metadata   Metadata `json:"metadata"`
	RawMessage json.RawMessage
}

// Metadata - The metadata for this detection
type Metadata struct {
	CID               string `json:"customerIDString"`
	Offset            uint64 `json:"offset"`
	Version           string `json:"version"`
	EventType         string `json:"eventType"`
	EventCreationTime uint64 `json:"eventCreationTime"`
}

// Event - The event data for the detection
type Event struct {
	OperationName     *string `json:"OperationName,omitempty"`
	ServiceName       *string `json:"ServiceName,omitempty"`
	UTCTimestamp      *uint64 `json:"UTCTimestamp,omitempty"`
	UserId            *string `json:"UserId,omitempty"`
	UserIp            *string `json:"UserIp,omitempty"`
	Success           *bool   `json:"Success,omitempty"`
	ComputerName      *string `json:"ComputerName,omitempty"`
	DetectDescription *string `json:"DetectDescription,omitempty"`
	Description       *string `json:"Description,omitempty"`
	DetectID          *string `json:"DetectId,omitempty"`
	CompositeId       *string `json:"CompositeId,omitempty"`
	FalconHostLink    *string `json:"FalconHostLink,omitempty"`

	IOARuleInstanceId      *string      `json:"IOARuleInstanceId,omitempty"`
	IOARuleInstanceVersion *json.Number `json:"IOARuleInstanceVersion,omitempty"`
	IOARuleName            *string      `json:"IOARuleName,omitempty"`
	IOARuleGroupName       *string      `json:"IOARuleGroupName,omitempty"`

	FileName                      *string                  `json:"FileName,omitempty"`
	FilePath                      *string                  `json:"FilePath,omitempty"`
	ProcessStartTime              *json.Number             `json:"ProcessStartTime,omitempty"`
	ProcessEndTime                *json.Number             `json:"ProcessEndTime,omitempty"`
	ProcessId                     *IntOrString             `json:"ProcessId,omitempty"`
	UserName                      *string                  `json:"UserName,omitempty"`
	DetectName                    *string                  `json:"DetectName,omitempty"`
	Name                          *string                  `json:"Name,omitempty"`
	CommandLine                   *string                  `json:"CommandLine,omitempty"`
	MD5                           *string                  `json:"MD5String,omitempty"`
	SHA1                          *string                  `json:"SHA1String,omitempty"`
	SHA256                        *string                  `json:"SHA256String,omitempty"`
	MachineDomain                 *string                  `json:"MachineDomain,omitempty"`
	SensorId                      *string                  `json:"SensorId,omitempty"`
	LocalIp                       *string                  `json:"LocalIP,omitempty"`
	MACAddress                    *string                  `json:"MACAddress,omitempty"`
	Objective                     *string                  `json:"Objective,omitempty"`
	PatternDispositionDescription *string                  `json:"PatternDispositionDescription,omitempty"`
	PatternDispositionValue       *json.Number             `json:"PatternDispositionValue,omitempty"`
	PatternDispositionFlags       *PatternDispositionFlags `json:"PatternDispositionFlags,omitempty"`
	DocumentsAccessed             *[]DocumentsAccessed     `json:"DocumentsAccessed,omitempty"`
	Commands                      *[]string                `json:"Commands,omitempty"`

	ParentProcessId          *IntOrString `json:"ParentProcessId,omitempty"`
	ParentCommandLine        *string      `json:"ParentCommandLine,omitempty"`
	ParentImageFileName      *string      `json:"ParentImageFileName,omitempty"`
	GrandparentCommandLine   *string      `json:"GrandparentCommandLine,omitempty"`
	GrandparentImageFileName *string      `json:"GrandparentImageFilename,omitempty"`

	NetworkAccesses   *[]NetworkAccess  `json:"NetworkAccesses,omitempty"`
	Severity          *float64          `json:"Severity,omitempty"`
	SeverityName      *string           `json:"SeverityName,omitempty"`
	Tactic            *string           `json:"Tactic,omitempty"`
	Technique         *string           `json:"Technique,omitempty"`
	AuditKeyValues    *[]AuditKeyValues `json:"AuditKeyValues,omitempty"`
	Attributes        AuditAttributes   `json:"Attributes,omitempty"`
	IncidentType      *String           `json:"IncidentType,omitempty"`
	IncidentStartTime *json.Number      `json:"IncidentStartTime,omitempty"`
	IncidentEndTime   *json.Number      `json:"IncidentEndTime,omitempty"`
	IncidentId        *string           `json:"IncidentId,omitempty"`
	State             *string           `json:"State,omitempty"`
	FineScore         *float64          `json:"FineScore,omitempty"`
	LateralMovement   *json.Number      `json:"LateralMovement,omitempty"`

	SessionId      *string      `json:"SessionId,omitempty"`
	HostnameField  *string      `json:"HostnameField,omitempty"`
	StartTimestamp *json.Number `json:"StartTimestamp,omitempty"`
	EndTimestamp   *json.Number `json:"EndTimestamp,omitempty"`

	// Additional holds the fields of the event that the typed fields above do
	// not: fields that Event does not declare, and fields whose value does
	// not fit the type of their typed field, such as a UTCTimestamp sent as a
	// string. Each value is kept as it came off the wire. Additional is
	// filled only when the Event is decoded as part of an EventItem, and is
	// left out when the Event is marshaled. EventItem.RawMessage keeps the
	// whole message.
	Additional map[string]json.RawMessage `json:"-"`
}

// eventFields and eventFieldsFolded map the json name of each typed field of
// Event, as declared and lowercased, to the index of the field.
var eventFields, eventFieldsFolded = jsonFieldIndex(reflect.TypeFor[Event]())

// jsonFieldIndex maps the json name of each field of struct type t, as
// declared and lowercased, to the index of the field, skipping the fields
// that encoding/json skips: unexported ones and those with a "-" tag.
func jsonFieldIndex(t reflect.Type) (declared, folded map[string]int) {
	declared = make(map[string]int, t.NumField())
	folded = make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = t.Field(i).Name
		}
		declared[name] = i
		folded[strings.ToLower(name)] = i
	}
	return declared, folded
}

// UnmarshalJSON decodes the metadata as usual, and the event one field at a
// time so that none is lost: each field goes to its typed field when Event has
// one and the value fits, and to Event.Additional otherwise. A name matches a
// typed field whatever its case. When several names match the same typed
// field, the exact name is tried first and then the others in sorted order,
// and the first whose value fits takes the field. Decoding replaces the whole
// item, except that a JSON null leaves it as it was. Only a message that is
// not a JSON object, an event that is not an object, or metadata that does not
// fit fails to decode.
func (item *EventItem) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	// The event field of envelope shadows the one of plain, which has the
	// fields of EventItem but not this method.
	type plain EventItem
	var envelope struct {
		Event json.RawMessage `json:"event"`
		plain
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode EventItem: %w", err)
	}
	event, err := decodeEvent(envelope.Event)
	if err != nil {
		return err
	}
	*item = EventItem(envelope.plain)
	item.Event = event
	return nil
}

// decodeEvent decodes the fields of an event payload into an Event, as
// EventItem.UnmarshalJSON describes. A missing or null payload is an empty
// Event.
func decodeEvent(data json.RawMessage) (Event, error) {
	var event Event
	if len(data) == 0 {
		return event, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return event, fmt.Errorf("decode event: %w", err)
	}
	typed := reflect.ValueOf(&event).Elem()
	held := make(map[int]bool, len(fields))
	take := func(name string, i int) {
		if !held[i] && decodeField(typed.Field(i), fields[name]) {
			held[i] = true
			delete(fields, name)
		}
	}
	for name := range fields {
		if i, ok := eventFields[name]; ok {
			take(name, i)
		}
	}
	// Sorted, so that the same case variant takes a field every time.
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if i, ok := eventFieldsFolded[strings.ToLower(name)]; ok {
			take(name, i)
		}
	}
	if len(fields) > 0 {
		event.Additional = fields
	}
	return event, nil
}

// decodeField decodes value into field and reports whether it fits. A field
// that the value does not fit is left zero, since encoding/json may have
// filled part of it before failing.
func decodeField(field reflect.Value, value json.RawMessage) bool {
	if err := json.Unmarshal(value, field.Addr().Interface()); err != nil {
		field.SetZero()
		return false
	}
	return true
}

type PatternDispositionFlags struct {
	Indicator                bool
	Detect                   bool
	InddetMask               bool
	SensorOnly               bool
	Rooting                  bool
	KillProcess              bool
	KillSubProcess           bool
	QuarantineMachine        bool
	QuarantineFile           bool
	PolicyDisabled           bool
	KillParent               bool
	OperationBlocked         bool
	ProcessBlocked           bool
	RegistryOperationBlocked bool
	CriticalProcessDisabled  bool
	BootupSafeguardEnabled   bool
	FsOperationBlocked       bool
}

type DocumentsAccessed struct {
	Timestamp uint64
	Filename  string
	FilePath  string
}

type AuditKeyValues struct {
	Key   string `json:"Key"`
	Value string `json:"ValueString"`
}

// AuditAttributes is the Attributes field of audit events, mapping each key to
// its value. APIActivityAuditEvent, UserActivityAuditEvent and
// AuthActivityAuditEvent send it as an object, and it marshals as one, with
// every value a string.
type AuditAttributes map[string]string

// UnmarshalJSON decodes Attributes sent as an object. A JSON null value becomes
// an empty string, and any other value that is not a JSON string keeps its
// JSON text. Any other form of Attributes fails to decode.
func (a *AuditAttributes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("decode Attributes: %w", err)
	}
	attributes := make(AuditAttributes, len(object))
	for key, value := range object {
		attributes[key] = auditValue(value)
	}
	*a = attributes
	return nil
}

// auditValue returns the text of an Attributes value: the string itself for a
// JSON string, empty for null, and the JSON text otherwise.
func auditValue(raw json.RawMessage) string {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	return value
}

// NetworkAccess - Network access information for this detection
type NetworkAccess struct {
	ConnectionDirection int    `json:"ConnectionDirection"`
	LocalAddress        string `json:"LocalAddress"        validate:"ip"`
	LocalPort           *int64 `json:"LocalPort"`
	Protocol            string `json:"Protocol"            validate:"oneof=tcp TCP udp UDP"`
	RemoteAddress       string `json:"RemoteAddress"       validate:"ip"`
	RemotePort          *int64 `json:"RemotePort"`
}
