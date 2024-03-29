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

// ModelsAPIPolicyEntity models API policy entity
//
// swagger:model models.APIPolicyEntity
type ModelsAPIPolicyEntity struct {

	// created at
	// Required: true
	CreatedAt *string `json:"created_at"`

	// description
	// Required: true
	Description *string `json:"description"`

	// is enabled
	// Required: true
	IsEnabled *bool `json:"is_enabled"`

	// name
	// Required: true
	Name *string `json:"name"`

	// policy data
	PolicyData *ModelsAPIPolicyData `json:"policy_data,omitempty"`

	// policy id
	// Required: true
	PolicyID *string `json:"policy_id"`

	// precedence
	// Required: true
	Precedence *int32 `json:"precedence"`

	// updated at
	// Required: true
	UpdatedAt *string `json:"updated_at"`
}

// Validate validates this models API policy entity
func (m *ModelsAPIPolicyEntity) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrecedence(formats); err != nil {
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

func (m *ModelsAPIPolicyEntity) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", m.CreatedAt); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validateIsEnabled(formats strfmt.Registry) error {

	if err := validate.Required("is_enabled", "body", m.IsEnabled); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validatePolicyData(formats strfmt.Registry) error {
	if swag.IsZero(m.PolicyData) { // not required
		return nil
	}

	if m.PolicyData != nil {
		if err := m.PolicyData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy_data")
			}
			return err
		}
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validatePolicyID(formats strfmt.Registry) error {

	if err := validate.Required("policy_id", "body", m.PolicyID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validatePrecedence(formats strfmt.Registry) error {

	if err := validate.Required("precedence", "body", m.Precedence); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPolicyEntity) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updated_at", "body", m.UpdatedAt); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this models API policy entity based on the context it is used
func (m *ModelsAPIPolicyEntity) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePolicyData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsAPIPolicyEntity) contextValidatePolicyData(ctx context.Context, formats strfmt.Registry) error {

	if m.PolicyData != nil {

		if swag.IsZero(m.PolicyData) { // not required
			return nil
		}

		if err := m.PolicyData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy_data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModelsAPIPolicyEntity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsAPIPolicyEntity) UnmarshalBinary(b []byte) error {
	var res ModelsAPIPolicyEntity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
