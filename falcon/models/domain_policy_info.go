// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DomainPolicyInfo domain policy info
//
// swagger:model domain.PolicyInfo
type DomainPolicyInfo struct {

	// created at
	// Required: true
	// Format: date-time
	CreatedAt *strfmt.DateTime `json:"CreatedAt"`

	// deleted at
	// Required: true
	// Format: date-time
	DeletedAt *strfmt.DateTime `json:"DeletedAt"`

	// ID
	// Required: true
	ID *int64 `json:"ID"`

	// updated at
	// Required: true
	// Format: date-time
	UpdatedAt *strfmt.DateTime `json:"UpdatedAt"`

	// account scope
	// Required: true
	AccountScope *string `json:"account_scope"`

	// alert logic
	AlertLogic string `json:"alert_logic,omitempty"`

	// api command
	APICommand string `json:"api_command,omitempty"`

	// asset type id
	AssetTypeID int32 `json:"asset_type_id,omitempty"`

	// attack tool
	AttackTool string `json:"attack_tool,omitempty"`

	// attack tool command
	AttackToolCommand string `json:"attack_tool_command,omitempty"`

	// attack types
	AttackTypes []string `json:"attack_types"`

	// cis benchmark ids
	CisBenchmarkIds []int64 `json:"cis_benchmark_ids"`

	// cisa benchmark ids
	CisaBenchmarkIds []int64 `json:"cisa_benchmark_ids"`

	// cli command
	CliCommand string `json:"cli_command,omitempty"`

	// cloud asset type
	CloudAssetType string `json:"cloud_asset_type,omitempty"`

	// cloud document
	CloudDocument string `json:"cloud_document,omitempty"`

	// cloud platform
	CloudPlatform int32 `json:"cloud_platform,omitempty"`

	// cloud platform type
	CloudPlatformType string `json:"cloud_platform_type,omitempty"`

	// cloud service
	CloudService int32 `json:"cloud_service,omitempty"`

	// cloud service friendly
	CloudServiceFriendly string `json:"cloud_service_friendly,omitempty"`

	// cloud service id
	CloudServiceID int32 `json:"cloud_service_id,omitempty"`

	// cloud service subtype
	CloudServiceSubtype string `json:"cloud_service_subtype,omitempty"`

	// cloud service type
	CloudServiceType string `json:"cloud_service_type,omitempty"`

	// compliance
	Compliance *DomainCompliance `json:"compliance,omitempty"`

	// confidence
	Confidence string `json:"confidence,omitempty"`

	// default severity
	DefaultSeverity string `json:"default_severity,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// event type
	EventType string `json:"event_type,omitempty"`

	// fql policy
	FqlPolicy string `json:"fql_policy,omitempty"`

	// hipaa benchmark ids
	HipaaBenchmarkIds []int64 `json:"hipaa_benchmark_ids"`

	// hitrust benchmark ids
	HitrustBenchmarkIds []int64 `json:"hitrust_benchmark_ids"`

	// internal only
	InternalOnly bool `json:"internal_only,omitempty"`

	// is enabled
	// Required: true
	IsEnabled *bool `json:"is_enabled"`

	// is remediable
	// Required: true
	IsRemediable *bool `json:"is_remediable"`

	// iso benchmark ids
	IsoBenchmarkIds []int64 `json:"iso_benchmark_ids"`

	// mitre attack cloud matrix
	MitreAttackCloudMatrix string `json:"mitre_attack_cloud_matrix,omitempty"`

	// mitre attack cloud subtype
	MitreAttackCloudSubtype string `json:"mitre_attack_cloud_subtype,omitempty"`

	// nist benchmark ids
	NistBenchmarkIds []int64 `json:"nist_benchmark_ids"`

	// pci benchmark ids
	PciBenchmarkIds []int64 `json:"pci_benchmark_ids"`

	// policy confidence score
	PolicyConfidenceScore int32 `json:"policy_confidence_score,omitempty"`

	// policy fail query
	PolicyFailQuery string `json:"policy_fail_query,omitempty"`

	// policy pass query
	PolicyPassQuery string `json:"policy_pass_query,omitempty"`

	// policy remediation
	PolicyRemediation string `json:"policy_remediation,omitempty"`

	// policy severity
	PolicySeverity int32 `json:"policy_severity,omitempty"`

	// policy severity score
	PolicySeverityScore int32 `json:"policy_severity_score,omitempty"`

	// policy statement
	PolicyStatement string `json:"policy_statement,omitempty"`

	// policy type
	PolicyType string `json:"policy_type,omitempty"`

	// remediation summary
	RemediationSummary string `json:"remediation_summary,omitempty"`

	// resource type friendly name
	ResourceTypeFriendlyName string `json:"resource_type_friendly_name,omitempty"`

	// resource type id
	ResourceTypeID string `json:"resource_type_id,omitempty"`

	// soc2 benchmark ids
	Soc2BenchmarkIds []int64 `json:"soc2_benchmark_ids"`

	// tactic
	Tactic string `json:"tactic,omitempty"`

	// tactic id
	TacticID string `json:"tactic_id,omitempty"`

	// tactic url
	TacticURL string `json:"tactic_url,omitempty"`

	// technique
	Technique string `json:"technique,omitempty"`

	// technique id
	TechniqueID string `json:"technique_id,omitempty"`

	// technique url
	TechniqueURL string `json:"technique_url,omitempty"`
}

// Validate validates this domain policy info
func (m *DomainPolicyInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeletedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAccountScope(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCompliance(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsRemediable(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainPolicyInfo) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("CreatedAt", "body", m.CreatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("CreatedAt", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainPolicyInfo) validateDeletedAt(formats strfmt.Registry) error {

	if err := validate.Required("DeletedAt", "body", m.DeletedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("DeletedAt", "body", "date-time", m.DeletedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainPolicyInfo) validateID(formats strfmt.Registry) error {

	if err := validate.Required("ID", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainPolicyInfo) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("UpdatedAt", "body", m.UpdatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("UpdatedAt", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainPolicyInfo) validateAccountScope(formats strfmt.Registry) error {

	if err := validate.Required("account_scope", "body", m.AccountScope); err != nil {
		return err
	}

	return nil
}

func (m *DomainPolicyInfo) validateCompliance(formats strfmt.Registry) error {
	if swag.IsZero(m.Compliance) { // not required
		return nil
	}

	if m.Compliance != nil {
		if err := m.Compliance.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("compliance")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("compliance")
			}
			return err
		}
	}

	return nil
}

func (m *DomainPolicyInfo) validateIsEnabled(formats strfmt.Registry) error {

	if err := validate.Required("is_enabled", "body", m.IsEnabled); err != nil {
		return err
	}

	return nil
}

func (m *DomainPolicyInfo) validateIsRemediable(formats strfmt.Registry) error {

	if err := validate.Required("is_remediable", "body", m.IsRemediable); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain policy info based on the context it is used
func (m *DomainPolicyInfo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCompliance(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainPolicyInfo) contextValidateCompliance(ctx context.Context, formats strfmt.Registry) error {

	if m.Compliance != nil {

		if swag.IsZero(m.Compliance) { // not required
			return nil
		}

		if err := m.Compliance.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("compliance")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("compliance")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainPolicyInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainPolicyInfo) UnmarshalBinary(b []byte) error {
	var res DomainPolicyInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
