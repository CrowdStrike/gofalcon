package streaming_models

// Detection - The structure for a detection
type Detection struct {
	Event    Event    `json:"event" validate:"dive"`
	MetaData MetaData `json:"metadata"`
}

// MetaData - The metadata for this detection
type MetaData struct {
	CID               string `json:"customerIDString"`
	Offset            uint64 `json:"offset"`
	Version           string `json:"version"`
	EventType         string `json:"eventType"`
	EventCreationTime uint64 `json:"eventCreationTime"`
}

// Event - The event data for the detection
type Event struct {
	OperationName     string  `json:"OperationName"`
	ServiceName       string  `json:"ServiceName"`
	UTCTimestamp      uint64  `json:"UTCTimestamp"`
	UserId            string  `json:"UserId"`
	UserIp            *string `json:"UserIp,omitempty"`
	Success           *bool   `json:"Success,omitempty"`
	ComputerName      *string `json:"ComputerName,omitempty"`
	DetectDescription *string `json:"DetectDescription,omitempty"`
	DetectID          string  `json:"DetectId,omitempty"`
	FalconHostLink    *string `json:"FalconHostLink,omitempty"`

	IOARuleInstanceId      *string `json:"IOARuleInstanceId,omitempty"`
	IOARuleInstanceVersion *uint64 `json:"IOARuleInstanceVersion,omitempty"`
	IOARuleName            *string `json:"IOARuleName,omitempty"`
	IOARuleGroupName       *string `json:"IOARuleGroupName,omitempty"`

	FileName                      *string                  `json:"FileName,omitempty"`
	FilePath                      *string                  `json:"FilePath,omitempty"`
	ProcessStartTime              *uint64                  `json:"ProcessStartTime,omitempty"`
	ProcessEndTime                *uint64                  `json:"ProcessEndTime,omitempty"`
	ProcessId                     *uint64                  `json:"ProcessId,omitempty"`
	UserName                      *string                  `json:"UserName,omitempty"`
	DetectName                    *string                  `json:"DetectName,omitempty"`
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
	PatternDispositionValue       *uint64                  `json:"PatternDispositionValue,omitempty"`
	PatternDispositionFlags       *PatternDispositionFlags `json:"PatternDispositionFlags,omitempty"`
	DocumentsAccessed             []DocumentsAccessed      `json:"DocumentsAccessed,omitempty"`
	Commands                      []string                 `json:"Commands,omitempty"`

	ParentProcesssId         *uint64 `json:"ParentProcessId,omitempty"`
	ParentCommandLine        *string `json:"ParentCommandLine,omitempty"`
	ParentImageFileName      *string `json:"ParentImageFileName,omitempty"`
	GrandparentCommandLine   *string `json:"GrandparentCommandLine,omitempty"`
	GrandparentImageFileName *string `json:"GrandparentImageFilename,omitempty"`

	NetworkAccesses   []NetworkAccess  `json:"NetworkAccesses,omitempty"`
	Severity          *float64         `json:"Severity,omitempty"`
	SeverityName      *string          `json:"SeverityName,omitempty"`
	Tactic            *string          `json:"Tactic,omitempty"`
	Technique         *string          `json:"Technique,omitempty"`
	AuditKeyValues    []AuditKeyValues `json:"AuditKeyValues"`
	IncidentType      *uint64          `json:"IncidentType,omitempty"`
	IncidentStartTime *uint64          `json:"IncidentStartTime,omitempty"`
	IncidentEndTime   *uint64          `json:"IncidentEndTime,omitempty"`
	State             *string          `json:"State,omitempty"`
	FineScore         *float64         `json:"FineScore,omitempty"`
	LateralMovement   *uint64          `json:"LateralMovement,omitempty"`

	SessionId      *string `json:"SessionId,omitempty"`
	HostnameField  *string `json:"HostnameField,omitempty"`
	StartTimestamp *uint64 `json:"StartTimestamp,omitempty"`
	EndTimestamp   *uint64 `json:"EndTimestamp,omitempty"`
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
