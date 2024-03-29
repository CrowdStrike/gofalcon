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

// ModelsCreateImageGroupRequest models create image group request
//
// swagger:model models.CreateImageGroupRequest
type ModelsCreateImageGroupRequest struct {

	// description
	// Required: true
	Description *string `json:"description"`

	// name
	// Required: true
	Name *string `json:"name"`

	// policy group data
	PolicyGroupData *ModelsAPIPolicyGroupData `json:"policy_group_data,omitempty"`

	// policy id
	PolicyID string `json:"policy_id,omitempty"`
}

// Validate validates this models create image group request
func (m *ModelsCreateImageGroupRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyGroupData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsCreateImageGroupRequest) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *ModelsCreateImageGroupRequest) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *ModelsCreateImageGroupRequest) validatePolicyGroupData(formats strfmt.Registry) error {
	if swag.IsZero(m.PolicyGroupData) { // not required
		return nil
	}

	if m.PolicyGroupData != nil {
		if err := m.PolicyGroupData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy_group_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy_group_data")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this models create image group request based on the context it is used
func (m *ModelsCreateImageGroupRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePolicyGroupData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsCreateImageGroupRequest) contextValidatePolicyGroupData(ctx context.Context, formats strfmt.Registry) error {

	if m.PolicyGroupData != nil {

		if swag.IsZero(m.PolicyGroupData) { // not required
			return nil
		}

		if err := m.PolicyGroupData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy_group_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy_group_data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModelsCreateImageGroupRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsCreateImageGroupRequest) UnmarshalBinary(b []byte) error {
	var res ModelsCreateImageGroupRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
