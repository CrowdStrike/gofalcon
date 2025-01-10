// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/crowdstrike/gofalcon/falcon/client/a_s_p_m"
	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/client/api_integrations"
	"github.com/crowdstrike/gofalcon/falcon/client/certificate_based_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_connect_aws"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_snapshots"
	"github.com/crowdstrike/gofalcon/falcon/client/compliance_assessments"
	"github.com/crowdstrike/gofalcon/falcon/client/configuration_assessment"
	"github.com/crowdstrike/gofalcon/falcon/client/configuration_assessment_evaluation_logic"
	"github.com/crowdstrike/gofalcon/falcon/client/container_alerts"
	"github.com/crowdstrike/gofalcon/falcon/client/container_detections"
	"github.com/crowdstrike/gofalcon/falcon/client/container_images"
	"github.com/crowdstrike/gofalcon/falcon/client/container_packages"
	"github.com/crowdstrike/gofalcon/falcon/client/container_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/client/cspg_iacapi"
	"github.com/crowdstrike/gofalcon/falcon/client/cspm_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_storage"
	"github.com/crowdstrike/gofalcon/falcon/client/d4c_registration"
	"github.com/crowdstrike/gofalcon/falcon/client/datascanner"
	"github.com/crowdstrike/gofalcon/falcon/client/delivery_settings"
	"github.com/crowdstrike/gofalcon/falcon/client/detects"
	"github.com/crowdstrike/gofalcon/falcon/client/device_content"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/discover"
	"github.com/crowdstrike/gofalcon/falcon/client/discover_iot"
	"github.com/crowdstrike/gofalcon/falcon/client/downloads_api"
	"github.com/crowdstrike/gofalcon/falcon/client/drift_indicators"
	"github.com/crowdstrike/gofalcon/falcon/client/event_schema"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/client/exposure_management"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_complete_dashboard"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_cli"
	"github.com/crowdstrike/gofalcon/falcon/client/falcon_container_image"
	"github.com/crowdstrike/gofalcon/falcon/client/falconx_sandbox"
	"github.com/crowdstrike/gofalcon/falcon/client/field_schema"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/foundry_logscale"
	"github.com/crowdstrike/gofalcon/falcon/client/handle"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/gofalcon/falcon/client/host_migration"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/humio_auth_proxy"
	"github.com/crowdstrike/gofalcon/falcon/client/identity_entities"
	"github.com/crowdstrike/gofalcon/falcon/client/identity_protection"
	"github.com/crowdstrike/gofalcon/falcon/client/image_assessment_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/incidents"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens_settings"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/client/iocs"
	"github.com/crowdstrike/gofalcon/falcon/client/kubernetes_protection"
	"github.com/crowdstrike/gofalcon/falcon/client/lookup_files"
	"github.com/crowdstrike/gofalcon/falcon/client/malquery"
	"github.com/crowdstrike/gofalcon/falcon/client/message_center"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/mobile_enrollment"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/client/oauth2"
	"github.com/crowdstrike/gofalcon/falcon/client/ods"
	"github.com/crowdstrike/gofalcon/falcon/client/operations"
	"github.com/crowdstrike/gofalcon/falcon/client/overwatch_dashboard"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/quarantine"
	"github.com/crowdstrike/gofalcon/falcon/client/quick_scan"
	"github.com/crowdstrike/gofalcon/falcon/client/quick_scan_pro"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_audit"
	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/client/report_executions"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/runtime_detections"
	"github.com/crowdstrike/gofalcon/falcon/client/sample_uploads"
	"github.com/crowdstrike/gofalcon/falcon/client/scheduled_reports"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_usage_api"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_evaluation_logic"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/client/tailored_intelligence"
	"github.com/crowdstrike/gofalcon/falcon/client/threatgraph"
	"github.com/crowdstrike/gofalcon/falcon/client/unidentified_containers"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
)

// Default crowd strike API specification HTTP client.
var Default = NewHTTPClient(nil)

const (
	// DefaultHost is the default Host
	// found in Meta (info) section of spec file
	DefaultHost string = "api.crowdstrike.com"
	// DefaultBasePath is the default BasePath
	// found in Meta (info) section of spec file
	DefaultBasePath string = "/"
)

// DefaultSchemes are the default schemes found in Meta (info) section of spec file
var DefaultSchemes = []string{"https"}

// NewHTTPClient creates a new crowd strike API specification HTTP client.
func NewHTTPClient(formats strfmt.Registry) *CrowdStrikeAPISpecification {
	return NewHTTPClientWithConfig(formats, nil)
}

// NewHTTPClientWithConfig creates a new crowd strike API specification HTTP client,
// using a customizable transport config.
func NewHTTPClientWithConfig(formats strfmt.Registry, cfg *TransportConfig) *CrowdStrikeAPISpecification {
	// ensure nullable parameters have default
	if cfg == nil {
		cfg = DefaultTransportConfig()
	}

	// create transport and client
	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return New(transport, formats)
}

// New creates a new crowd strike API specification client
func New(transport runtime.ClientTransport, formats strfmt.Registry) *CrowdStrikeAPISpecification {
	// ensure nullable parameters have default
	if formats == nil {
		formats = strfmt.Default
	}

	cli := new(CrowdStrikeAPISpecification)
	cli.Transport = transport
	cli.Aspm = a_s_p_m.New(transport, formats)
	cli.Alerts = alerts.New(transport, formats)
	cli.APIIntegrations = api_integrations.New(transport, formats)
	cli.CertificateBasedExclusions = certificate_based_exclusions.New(transport, formats)
	cli.CloudConnectAws = cloud_connect_aws.New(transport, formats)
	cli.CloudSecurityAssets = cloud_security_assets.New(transport, formats)
	cli.CloudSnapshots = cloud_snapshots.New(transport, formats)
	cli.ComplianceAssessments = compliance_assessments.New(transport, formats)
	cli.ConfigurationAssessment = configuration_assessment.New(transport, formats)
	cli.ConfigurationAssessmentEvaluationLogic = configuration_assessment_evaluation_logic.New(transport, formats)
	cli.ContainerAlerts = container_alerts.New(transport, formats)
	cli.ContainerDetections = container_detections.New(transport, formats)
	cli.ContainerImages = container_images.New(transport, formats)
	cli.ContainerPackages = container_packages.New(transport, formats)
	cli.ContainerVulnerabilities = container_vulnerabilities.New(transport, formats)
	cli.ContentUpdatePolicies = content_update_policies.New(transport, formats)
	cli.CorrelationRules = correlation_rules.New(transport, formats)
	cli.CspgIacapi = cspg_iacapi.New(transport, formats)
	cli.CspmRegistration = cspm_registration.New(transport, formats)
	cli.CustomIoa = custom_ioa.New(transport, formats)
	cli.CustomStorage = custom_storage.New(transport, formats)
	cli.D4cRegistration = d4c_registration.New(transport, formats)
	cli.Datascanner = datascanner.New(transport, formats)
	cli.DeliverySettings = delivery_settings.New(transport, formats)
	cli.Detects = detects.New(transport, formats)
	cli.DeviceContent = device_content.New(transport, formats)
	cli.DeviceControlPolicies = device_control_policies.New(transport, formats)
	cli.Discover = discover.New(transport, formats)
	cli.DiscoverIot = discover_iot.New(transport, formats)
	cli.DownloadsAPI = downloads_api.New(transport, formats)
	cli.DriftIndicators = drift_indicators.New(transport, formats)
	cli.EventSchema = event_schema.New(transport, formats)
	cli.EventStreams = event_streams.New(transport, formats)
	cli.ExposureManagement = exposure_management.New(transport, formats)
	cli.FalconCompleteDashboard = falcon_complete_dashboard.New(transport, formats)
	cli.FalconContainer = falcon_container.New(transport, formats)
	cli.FalconContainerCli = falcon_container_cli.New(transport, formats)
	cli.FalconContainerImage = falcon_container_image.New(transport, formats)
	cli.FalconxSandbox = falconx_sandbox.New(transport, formats)
	cli.FieldSchema = field_schema.New(transport, formats)
	cli.Filevantage = filevantage.New(transport, formats)
	cli.FirewallManagement = firewall_management.New(transport, formats)
	cli.FirewallPolicies = firewall_policies.New(transport, formats)
	cli.FoundryLogscale = foundry_logscale.New(transport, formats)
	cli.Handle = handle.New(transport, formats)
	cli.HostGroup = host_group.New(transport, formats)
	cli.HostMigration = host_migration.New(transport, formats)
	cli.Hosts = hosts.New(transport, formats)
	cli.HumioAuthProxy = humio_auth_proxy.New(transport, formats)
	cli.IdentityEntities = identity_entities.New(transport, formats)
	cli.IdentityProtection = identity_protection.New(transport, formats)
	cli.ImageAssessmentPolicies = image_assessment_policies.New(transport, formats)
	cli.Incidents = incidents.New(transport, formats)
	cli.InstallationTokens = installation_tokens.New(transport, formats)
	cli.InstallationTokensSettings = installation_tokens_settings.New(transport, formats)
	cli.Intel = intel.New(transport, formats)
	cli.IoaExclusions = ioa_exclusions.New(transport, formats)
	cli.Ioc = ioc.New(transport, formats)
	cli.Iocs = iocs.New(transport, formats)
	cli.KubernetesProtection = kubernetes_protection.New(transport, formats)
	cli.LookupFiles = lookup_files.New(transport, formats)
	cli.Malquery = malquery.New(transport, formats)
	cli.MessageCenter = message_center.New(transport, formats)
	cli.MlExclusions = ml_exclusions.New(transport, formats)
	cli.MobileEnrollment = mobile_enrollment.New(transport, formats)
	cli.Mssp = mssp.New(transport, formats)
	cli.Oauth2 = oauth2.New(transport, formats)
	cli.Ods = ods.New(transport, formats)
	cli.Operations = operations.New(transport, formats)
	cli.OverwatchDashboard = overwatch_dashboard.New(transport, formats)
	cli.PreventionPolicies = prevention_policies.New(transport, formats)
	cli.Quarantine = quarantine.New(transport, formats)
	cli.QuickScan = quick_scan.New(transport, formats)
	cli.QuickScanPro = quick_scan_pro.New(transport, formats)
	cli.RealTimeResponse = real_time_response.New(transport, formats)
	cli.RealTimeResponseAdmin = real_time_response_admin.New(transport, formats)
	cli.RealTimeResponseAudit = real_time_response_audit.New(transport, formats)
	cli.Recon = recon.New(transport, formats)
	cli.ReportExecutions = report_executions.New(transport, formats)
	cli.ResponsePolicies = response_policies.New(transport, formats)
	cli.RuntimeDetections = runtime_detections.New(transport, formats)
	cli.SampleUploads = sample_uploads.New(transport, formats)
	cli.ScheduledReports = scheduled_reports.New(transport, formats)
	cli.SensorDownload = sensor_download.New(transport, formats)
	cli.SensorUpdatePolicies = sensor_update_policies.New(transport, formats)
	cli.SensorUsageAPI = sensor_usage_api.New(transport, formats)
	cli.SensorVisibilityExclusions = sensor_visibility_exclusions.New(transport, formats)
	cli.SpotlightEvaluationLogic = spotlight_evaluation_logic.New(transport, formats)
	cli.SpotlightVulnerabilities = spotlight_vulnerabilities.New(transport, formats)
	cli.TailoredIntelligence = tailored_intelligence.New(transport, formats)
	cli.Threatgraph = threatgraph.New(transport, formats)
	cli.UnidentifiedContainers = unidentified_containers.New(transport, formats)
	cli.UserManagement = user_management.New(transport, formats)
	cli.Workflows = workflows.New(transport, formats)
	cli.ZeroTrustAssessment = zero_trust_assessment.New(transport, formats)
	return cli
}

// DefaultTransportConfig creates a TransportConfig with the
// default settings taken from the meta section of the spec file.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		Host:     DefaultHost,
		BasePath: DefaultBasePath,
		Schemes:  DefaultSchemes,
	}
}

// TransportConfig contains the transport related info,
// found in the meta section of the spec file.
type TransportConfig struct {
	Host     string
	BasePath string
	Schemes  []string
}

// WithHost overrides the default host,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithHost(host string) *TransportConfig {
	cfg.Host = host
	return cfg
}

// WithBasePath overrides the default basePath,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithBasePath(basePath string) *TransportConfig {
	cfg.BasePath = basePath
	return cfg
}

// WithSchemes overrides the default schemes,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithSchemes(schemes []string) *TransportConfig {
	cfg.Schemes = schemes
	return cfg
}

// CrowdStrikeAPISpecification is a client for crowd strike API specification
type CrowdStrikeAPISpecification struct {
	Aspm a_s_p_m.ClientService

	Alerts alerts.ClientService

	APIIntegrations api_integrations.ClientService

	CertificateBasedExclusions certificate_based_exclusions.ClientService

	CloudConnectAws cloud_connect_aws.ClientService

	CloudSecurityAssets cloud_security_assets.ClientService

	CloudSnapshots cloud_snapshots.ClientService

	ComplianceAssessments compliance_assessments.ClientService

	ConfigurationAssessment configuration_assessment.ClientService

	ConfigurationAssessmentEvaluationLogic configuration_assessment_evaluation_logic.ClientService

	ContainerAlerts container_alerts.ClientService

	ContainerDetections container_detections.ClientService

	ContainerImages container_images.ClientService

	ContainerPackages container_packages.ClientService

	ContainerVulnerabilities container_vulnerabilities.ClientService

	ContentUpdatePolicies content_update_policies.ClientService

	CorrelationRules correlation_rules.ClientService

	CspgIacapi cspg_iacapi.ClientService

	CspmRegistration cspm_registration.ClientService

	CustomIoa custom_ioa.ClientService

	CustomStorage custom_storage.ClientService

	D4cRegistration d4c_registration.ClientService

	Datascanner datascanner.ClientService

	DeliverySettings delivery_settings.ClientService

	Detects detects.ClientService

	DeviceContent device_content.ClientService

	DeviceControlPolicies device_control_policies.ClientService

	Discover discover.ClientService

	DiscoverIot discover_iot.ClientService

	DownloadsAPI downloads_api.ClientService

	DriftIndicators drift_indicators.ClientService

	EventSchema event_schema.ClientService

	EventStreams event_streams.ClientService

	ExposureManagement exposure_management.ClientService

	FalconCompleteDashboard falcon_complete_dashboard.ClientService

	FalconContainer falcon_container.ClientService

	FalconContainerCli falcon_container_cli.ClientService

	FalconContainerImage falcon_container_image.ClientService

	FalconxSandbox falconx_sandbox.ClientService

	FieldSchema field_schema.ClientService

	Filevantage filevantage.ClientService

	FirewallManagement firewall_management.ClientService

	FirewallPolicies firewall_policies.ClientService

	FoundryLogscale foundry_logscale.ClientService

	Handle handle.ClientService

	HostGroup host_group.ClientService

	HostMigration host_migration.ClientService

	Hosts hosts.ClientService

	HumioAuthProxy humio_auth_proxy.ClientService

	IdentityEntities identity_entities.ClientService

	IdentityProtection identity_protection.ClientService

	ImageAssessmentPolicies image_assessment_policies.ClientService

	Incidents incidents.ClientService

	InstallationTokens installation_tokens.ClientService

	InstallationTokensSettings installation_tokens_settings.ClientService

	Intel intel.ClientService

	IoaExclusions ioa_exclusions.ClientService

	Ioc ioc.ClientService

	Iocs iocs.ClientService

	KubernetesProtection kubernetes_protection.ClientService

	LookupFiles lookup_files.ClientService

	Malquery malquery.ClientService

	MessageCenter message_center.ClientService

	MlExclusions ml_exclusions.ClientService

	MobileEnrollment mobile_enrollment.ClientService

	Mssp mssp.ClientService

	Oauth2 oauth2.ClientService

	Ods ods.ClientService

	Operations operations.ClientService

	OverwatchDashboard overwatch_dashboard.ClientService

	PreventionPolicies prevention_policies.ClientService

	Quarantine quarantine.ClientService

	QuickScan quick_scan.ClientService

	QuickScanPro quick_scan_pro.ClientService

	RealTimeResponse real_time_response.ClientService

	RealTimeResponseAdmin real_time_response_admin.ClientService

	RealTimeResponseAudit real_time_response_audit.ClientService

	Recon recon.ClientService

	ReportExecutions report_executions.ClientService

	ResponsePolicies response_policies.ClientService

	RuntimeDetections runtime_detections.ClientService

	SampleUploads sample_uploads.ClientService

	ScheduledReports scheduled_reports.ClientService

	SensorDownload sensor_download.ClientService

	SensorUpdatePolicies sensor_update_policies.ClientService

	SensorUsageAPI sensor_usage_api.ClientService

	SensorVisibilityExclusions sensor_visibility_exclusions.ClientService

	SpotlightEvaluationLogic spotlight_evaluation_logic.ClientService

	SpotlightVulnerabilities spotlight_vulnerabilities.ClientService

	TailoredIntelligence tailored_intelligence.ClientService

	Threatgraph threatgraph.ClientService

	UnidentifiedContainers unidentified_containers.ClientService

	UserManagement user_management.ClientService

	Workflows workflows.ClientService

	ZeroTrustAssessment zero_trust_assessment.ClientService

	Transport runtime.ClientTransport
}

// SetTransport changes the transport on the client and all its subresources
func (c *CrowdStrikeAPISpecification) SetTransport(transport runtime.ClientTransport) {
	c.Transport = transport
	c.Aspm.SetTransport(transport)
	c.Alerts.SetTransport(transport)
	c.APIIntegrations.SetTransport(transport)
	c.CertificateBasedExclusions.SetTransport(transport)
	c.CloudConnectAws.SetTransport(transport)
	c.CloudSecurityAssets.SetTransport(transport)
	c.CloudSnapshots.SetTransport(transport)
	c.ComplianceAssessments.SetTransport(transport)
	c.ConfigurationAssessment.SetTransport(transport)
	c.ConfigurationAssessmentEvaluationLogic.SetTransport(transport)
	c.ContainerAlerts.SetTransport(transport)
	c.ContainerDetections.SetTransport(transport)
	c.ContainerImages.SetTransport(transport)
	c.ContainerPackages.SetTransport(transport)
	c.ContainerVulnerabilities.SetTransport(transport)
	c.ContentUpdatePolicies.SetTransport(transport)
	c.CorrelationRules.SetTransport(transport)
	c.CspgIacapi.SetTransport(transport)
	c.CspmRegistration.SetTransport(transport)
	c.CustomIoa.SetTransport(transport)
	c.CustomStorage.SetTransport(transport)
	c.D4cRegistration.SetTransport(transport)
	c.Datascanner.SetTransport(transport)
	c.DeliverySettings.SetTransport(transport)
	c.Detects.SetTransport(transport)
	c.DeviceContent.SetTransport(transport)
	c.DeviceControlPolicies.SetTransport(transport)
	c.Discover.SetTransport(transport)
	c.DiscoverIot.SetTransport(transport)
	c.DownloadsAPI.SetTransport(transport)
	c.DriftIndicators.SetTransport(transport)
	c.EventSchema.SetTransport(transport)
	c.EventStreams.SetTransport(transport)
	c.ExposureManagement.SetTransport(transport)
	c.FalconCompleteDashboard.SetTransport(transport)
	c.FalconContainer.SetTransport(transport)
	c.FalconContainerCli.SetTransport(transport)
	c.FalconContainerImage.SetTransport(transport)
	c.FalconxSandbox.SetTransport(transport)
	c.FieldSchema.SetTransport(transport)
	c.Filevantage.SetTransport(transport)
	c.FirewallManagement.SetTransport(transport)
	c.FirewallPolicies.SetTransport(transport)
	c.FoundryLogscale.SetTransport(transport)
	c.Handle.SetTransport(transport)
	c.HostGroup.SetTransport(transport)
	c.HostMigration.SetTransport(transport)
	c.Hosts.SetTransport(transport)
	c.HumioAuthProxy.SetTransport(transport)
	c.IdentityEntities.SetTransport(transport)
	c.IdentityProtection.SetTransport(transport)
	c.ImageAssessmentPolicies.SetTransport(transport)
	c.Incidents.SetTransport(transport)
	c.InstallationTokens.SetTransport(transport)
	c.InstallationTokensSettings.SetTransport(transport)
	c.Intel.SetTransport(transport)
	c.IoaExclusions.SetTransport(transport)
	c.Ioc.SetTransport(transport)
	c.Iocs.SetTransport(transport)
	c.KubernetesProtection.SetTransport(transport)
	c.LookupFiles.SetTransport(transport)
	c.Malquery.SetTransport(transport)
	c.MessageCenter.SetTransport(transport)
	c.MlExclusions.SetTransport(transport)
	c.MobileEnrollment.SetTransport(transport)
	c.Mssp.SetTransport(transport)
	c.Oauth2.SetTransport(transport)
	c.Ods.SetTransport(transport)
	c.Operations.SetTransport(transport)
	c.OverwatchDashboard.SetTransport(transport)
	c.PreventionPolicies.SetTransport(transport)
	c.Quarantine.SetTransport(transport)
	c.QuickScan.SetTransport(transport)
	c.QuickScanPro.SetTransport(transport)
	c.RealTimeResponse.SetTransport(transport)
	c.RealTimeResponseAdmin.SetTransport(transport)
	c.RealTimeResponseAudit.SetTransport(transport)
	c.Recon.SetTransport(transport)
	c.ReportExecutions.SetTransport(transport)
	c.ResponsePolicies.SetTransport(transport)
	c.RuntimeDetections.SetTransport(transport)
	c.SampleUploads.SetTransport(transport)
	c.ScheduledReports.SetTransport(transport)
	c.SensorDownload.SetTransport(transport)
	c.SensorUpdatePolicies.SetTransport(transport)
	c.SensorUsageAPI.SetTransport(transport)
	c.SensorVisibilityExclusions.SetTransport(transport)
	c.SpotlightEvaluationLogic.SetTransport(transport)
	c.SpotlightVulnerabilities.SetTransport(transport)
	c.TailoredIntelligence.SetTransport(transport)
	c.Threatgraph.SetTransport(transport)
	c.UnidentifiedContainers.SetTransport(transport)
	c.UserManagement.SetTransport(transport)
	c.Workflows.SetTransport(transport)
	c.ZeroTrustAssessment.SetTransport(transport)
}
