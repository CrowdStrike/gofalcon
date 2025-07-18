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

// ResourcesComplianceControl resources compliance control
//
// swagger:model resources.ComplianceControl
type ResourcesComplianceControl struct {

	// account id
	// Required: true
	AccountID *string `json:"account_id"`

	// account name
	// Required: true
	AccountName *string `json:"account_name"`

	// assessment id
	// Required: true
	AssessmentID *string `json:"assessment_id"`

	// cloud groups
	CloudGroups []*DomainCloudScope `json:"cloud_groups"`

	// cloud groups v2
	CloudGroupsV2 []*DomainCloudGroup `json:"cloud_groups_v2"`

	// cloud labels
	CloudLabels []*ClassificationLabel `json:"cloud_labels"`

	// cloud provider
	// Required: true
	CloudProvider *string `json:"cloud_provider"`

	// control
	// Required: true
	Control *ResourcesControlInfo `json:"control"`

	// gcrn
	Gcrn string `json:"gcrn,omitempty"`

	// groups
	Groups []string `json:"groups"`

	// last evaluated
	// Required: true
	// Format: date-time
	LastEvaluated *strfmt.DateTime `json:"last_evaluated"`

	// region
	// Required: true
	Region *string `json:"region"`

	// resource counts
	// Required: true
	ResourceCounts *ResourceCounts `json:"resource_counts"`

	// resource provider
	// Required: true
	ResourceProvider *string `json:"resource_provider"`

	// resource type
	// Required: true
	ResourceType *string `json:"resource_type"`

	// resource type name
	// Required: true
	ResourceTypeName *string `json:"resource_type_name"`

	// rules
	// Required: true
	Rules []*ResourcesRule `json:"rules"`

	// service
	// Required: true
	Service *string `json:"service"`

	// service category
	// Required: true
	ServiceCategory *string `json:"service_category"`

	// severities
	// Required: true
	Severities []string `json:"severities"`

	// tags
	Tags map[string]string `json:"tags,omitempty"`
}

// Validate validates this resources compliance control
func (m *ResourcesComplianceControl) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAccountName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssessmentID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudGroups(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudGroupsV2(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateControl(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastEvaluated(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRegion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceCounts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceTypeName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRules(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceCategory(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverities(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResourcesComplianceControl) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("account_id", "body", m.AccountID); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateAccountName(formats strfmt.Registry) error {

	if err := validate.Required("account_name", "body", m.AccountName); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateAssessmentID(formats strfmt.Registry) error {

	if err := validate.Required("assessment_id", "body", m.AssessmentID); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateCloudGroups(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudGroups) { // not required
		return nil
	}

	for i := 0; i < len(m.CloudGroups); i++ {
		if swag.IsZero(m.CloudGroups[i]) { // not required
			continue
		}

		if m.CloudGroups[i] != nil {
			if err := m.CloudGroups[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) validateCloudGroupsV2(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudGroupsV2) { // not required
		return nil
	}

	for i := 0; i < len(m.CloudGroupsV2); i++ {
		if swag.IsZero(m.CloudGroupsV2[i]) { // not required
			continue
		}

		if m.CloudGroupsV2[i] != nil {
			if err := m.CloudGroupsV2[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_groups_v2" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_groups_v2" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) validateCloudLabels(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudLabels) { // not required
		return nil
	}

	for i := 0; i < len(m.CloudLabels); i++ {
		if swag.IsZero(m.CloudLabels[i]) { // not required
			continue
		}

		if m.CloudLabels[i] != nil {
			if err := m.CloudLabels[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) validateCloudProvider(formats strfmt.Registry) error {

	if err := validate.Required("cloud_provider", "body", m.CloudProvider); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateControl(formats strfmt.Registry) error {

	if err := validate.Required("control", "body", m.Control); err != nil {
		return err
	}

	if m.Control != nil {
		if err := m.Control.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("control")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("control")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesComplianceControl) validateLastEvaluated(formats strfmt.Registry) error {

	if err := validate.Required("last_evaluated", "body", m.LastEvaluated); err != nil {
		return err
	}

	if err := validate.FormatOf("last_evaluated", "body", "date-time", m.LastEvaluated.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateRegion(formats strfmt.Registry) error {

	if err := validate.Required("region", "body", m.Region); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateResourceCounts(formats strfmt.Registry) error {

	if err := validate.Required("resource_counts", "body", m.ResourceCounts); err != nil {
		return err
	}

	if m.ResourceCounts != nil {
		if err := m.ResourceCounts.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("resource_counts")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("resource_counts")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesComplianceControl) validateResourceProvider(formats strfmt.Registry) error {

	if err := validate.Required("resource_provider", "body", m.ResourceProvider); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateResourceType(formats strfmt.Registry) error {

	if err := validate.Required("resource_type", "body", m.ResourceType); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateResourceTypeName(formats strfmt.Registry) error {

	if err := validate.Required("resource_type_name", "body", m.ResourceTypeName); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateRules(formats strfmt.Registry) error {

	if err := validate.Required("rules", "body", m.Rules); err != nil {
		return err
	}

	for i := 0; i < len(m.Rules); i++ {
		if swag.IsZero(m.Rules[i]) { // not required
			continue
		}

		if m.Rules[i] != nil {
			if err := m.Rules[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) validateService(formats strfmt.Registry) error {

	if err := validate.Required("service", "body", m.Service); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateServiceCategory(formats strfmt.Registry) error {

	if err := validate.Required("service_category", "body", m.ServiceCategory); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesComplianceControl) validateSeverities(formats strfmt.Registry) error {

	if err := validate.Required("severities", "body", m.Severities); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this resources compliance control based on the context it is used
func (m *ResourcesComplianceControl) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCloudGroups(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCloudGroupsV2(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCloudLabels(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateControl(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateResourceCounts(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRules(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResourcesComplianceControl) contextValidateCloudGroups(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CloudGroups); i++ {

		if m.CloudGroups[i] != nil {

			if swag.IsZero(m.CloudGroups[i]) { // not required
				return nil
			}

			if err := m.CloudGroups[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) contextValidateCloudGroupsV2(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CloudGroupsV2); i++ {

		if m.CloudGroupsV2[i] != nil {

			if swag.IsZero(m.CloudGroupsV2[i]) { // not required
				return nil
			}

			if err := m.CloudGroupsV2[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_groups_v2" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_groups_v2" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) contextValidateCloudLabels(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CloudLabels); i++ {

		if m.CloudLabels[i] != nil {

			if swag.IsZero(m.CloudLabels[i]) { // not required
				return nil
			}

			if err := m.CloudLabels[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesComplianceControl) contextValidateControl(ctx context.Context, formats strfmt.Registry) error {

	if m.Control != nil {

		if err := m.Control.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("control")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("control")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesComplianceControl) contextValidateResourceCounts(ctx context.Context, formats strfmt.Registry) error {

	if m.ResourceCounts != nil {

		if err := m.ResourceCounts.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("resource_counts")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("resource_counts")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesComplianceControl) contextValidateRules(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Rules); i++ {

		if m.Rules[i] != nil {

			if swag.IsZero(m.Rules[i]) { // not required
				return nil
			}

			if err := m.Rules[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ResourcesComplianceControl) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResourcesComplianceControl) UnmarshalBinary(b []byte) error {
	var res ResourcesComplianceControl
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
