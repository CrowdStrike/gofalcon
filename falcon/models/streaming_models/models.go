package streaming_models

import "encoding/json"

// EventItem - The structure for parent model
type EventItem struct {
	Event    Event    `json:"event" validate:"dive"`
	Metadata Metadata `json:"metadata"`
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

// NetworkAccess - Network access information for this detection
type NetworkAccess struct {
	ConnectionDirection int    `json:"ConnectionDirection"`
	LocalAddress        string `json:"LocalAddress" validate:"ip"`
	LocalPort           *int64 `json:"LocalPort"`
	Protocol            string `json:"Protocol" validate:"oneof=tcp TCP udp UDP"`
	RemoteAddress       string `json:"RemoteAddress" validate:"ip"`
	RemotePort          *int64 `json:"RemotePort"`
}
