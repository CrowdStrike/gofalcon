// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DomainCIDPolicyAssignments domain c ID policy assignments
//
// swagger:model domain.CIDPolicyAssignments
type DomainCIDPolicyAssignments struct {

	// account scope
	AccountScope string `json:"account_scope,omitempty"`

	// attack types
	AttackTypes []string `json:"attack_types"`

	// cid
	Cid string `json:"cid,omitempty"`

	// cis benchmark
	CisBenchmark []*DomainBenchmark `json:"cis_benchmark"`

	// cloud asset type
	CloudAssetType string `json:"cloud_asset_type,omitempty"`

	// cloud asset type id
	CloudAssetTypeID int32 `json:"cloud_asset_type_id,omitempty"`

	// cloud provider
	CloudProvider string `json:"cloud_provider,omitempty"`

	// cloud service
	CloudService string `json:"cloud_service,omitempty"`

	// cloud service friendly
	CloudServiceFriendly string `json:"cloud_service_friendly,omitempty"`

	// cloud service subtype
	CloudServiceSubtype string `json:"cloud_service_subtype,omitempty"`

	// created at
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// default severity
	DefaultSeverity string `json:"default_severity,omitempty"`

	// fql policy
	FqlPolicy string `json:"fql_policy,omitempty"`

	// is remediable
	// Required: true
	IsRemediable *bool `json:"is_remediable"`

	// name
	Name string `json:"name,omitempty"`

	// nist benchmark
	NistBenchmark []*DomainBenchmark `json:"nist_benchmark"`

	// pci benchmark
	PciBenchmark []*DomainBenchmark `json:"pci_benchmark"`

	// policy id
	PolicyID int32 `json:"policy_id,omitempty"`

	// policy settings
	PolicySettings []*DomainPolicySettingByAccountAndRegion `json:"policy_settings"`

	// policy timestamp
	// Format: date-time
	PolicyTimestamp strfmt.DateTime `json:"policy_timestamp,omitempty"`

	// policy type
	PolicyType string `json:"policy_type,omitempty"`

	// remediation summary
	RemediationSummary string `json:"remediation_summary,omitempty"`

	// soc2 benchmark
	Soc2Benchmark []*DomainBenchmark `json:"soc2_benchmark"`

	// updated at
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at,omitempty"`
}

// Validate validates this domain c ID policy assignments
func (m *DomainCIDPolicyAssignments) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCisBenchmark(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsRemediable(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNistBenchmark(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePciBenchmark(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicySettings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSoc2Benchmark(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainCIDPolicyAssignments) validateCisBenchmark(formats strfmt.Registry) error {
	if swag.IsZero(m.CisBenchmark) { // not required
		return nil
	}

	for i := 0; i < len(m.CisBenchmark); i++ {
		if swag.IsZero(m.CisBenchmark[i]) { // not required
			continue
		}

		if m.CisBenchmark[i] != nil {
			if err := m.CisBenchmark[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cis_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cis_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validateIsRemediable(formats strfmt.Registry) error {

	if err := validate.Required("is_remediable", "body", m.IsRemediable); err != nil {
		return err
	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validateNistBenchmark(formats strfmt.Registry) error {
	if swag.IsZero(m.NistBenchmark) { // not required
		return nil
	}

	for i := 0; i < len(m.NistBenchmark); i++ {
		if swag.IsZero(m.NistBenchmark[i]) { // not required
			continue
		}

		if m.NistBenchmark[i] != nil {
			if err := m.NistBenchmark[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("nist_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("nist_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validatePciBenchmark(formats strfmt.Registry) error {
	if swag.IsZero(m.PciBenchmark) { // not required
		return nil
	}

	for i := 0; i < len(m.PciBenchmark); i++ {
		if swag.IsZero(m.PciBenchmark[i]) { // not required
			continue
		}

		if m.PciBenchmark[i] != nil {
			if err := m.PciBenchmark[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("pci_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("pci_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validatePolicySettings(formats strfmt.Registry) error {
	if swag.IsZero(m.PolicySettings) { // not required
		return nil
	}

	for i := 0; i < len(m.PolicySettings); i++ {
		if swag.IsZero(m.PolicySettings[i]) { // not required
			continue
		}

		if m.PolicySettings[i] != nil {
			if err := m.PolicySettings[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policy_settings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policy_settings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validatePolicyTimestamp(formats strfmt.Registry) error {
	if swag.IsZero(m.PolicyTimestamp) { // not required
		return nil
	}

	if err := validate.FormatOf("policy_timestamp", "body", "date-time", m.PolicyTimestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validateSoc2Benchmark(formats strfmt.Registry) error {
	if swag.IsZero(m.Soc2Benchmark) { // not required
		return nil
	}

	for i := 0; i < len(m.Soc2Benchmark); i++ {
		if swag.IsZero(m.Soc2Benchmark[i]) { // not required
			continue
		}

		if m.Soc2Benchmark[i] != nil {
			if err := m.Soc2Benchmark[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("soc2_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("soc2_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) validateUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain c ID policy assignments based on the context it is used
func (m *DomainCIDPolicyAssignments) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCisBenchmark(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNistBenchmark(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePciBenchmark(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePolicySettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSoc2Benchmark(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainCIDPolicyAssignments) contextValidateCisBenchmark(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CisBenchmark); i++ {

		if m.CisBenchmark[i] != nil {

			if swag.IsZero(m.CisBenchmark[i]) { // not required
				return nil
			}

			if err := m.CisBenchmark[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cis_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cis_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) contextValidateNistBenchmark(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NistBenchmark); i++ {

		if m.NistBenchmark[i] != nil {

			if swag.IsZero(m.NistBenchmark[i]) { // not required
				return nil
			}

			if err := m.NistBenchmark[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("nist_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("nist_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) contextValidatePciBenchmark(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.PciBenchmark); i++ {

		if m.PciBenchmark[i] != nil {

			if swag.IsZero(m.PciBenchmark[i]) { // not required
				return nil
			}

			if err := m.PciBenchmark[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("pci_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("pci_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) contextValidatePolicySettings(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.PolicySettings); i++ {

		if m.PolicySettings[i] != nil {

			if swag.IsZero(m.PolicySettings[i]) { // not required
				return nil
			}

			if err := m.PolicySettings[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policy_settings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policy_settings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainCIDPolicyAssignments) contextValidateSoc2Benchmark(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Soc2Benchmark); i++ {

		if m.Soc2Benchmark[i] != nil {

			if swag.IsZero(m.Soc2Benchmark[i]) { // not required
				return nil
			}

			if err := m.Soc2Benchmark[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("soc2_benchmark" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("soc2_benchmark" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainCIDPolicyAssignments) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainCIDPolicyAssignments) UnmarshalBinary(b []byte) error {
	var res DomainCIDPolicyAssignments
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
