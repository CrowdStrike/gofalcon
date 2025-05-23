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

// DomainContentUpdateSettingsV1 domain content update settings v1
//
// swagger:model domain.ContentUpdateSettingsV1
type DomainContentUpdateSettingsV1 struct {

	// ring assignment settings
	// Required: true
	RingAssignmentSettings []*DomainRingAssignmentSettingsV1 `json:"ring_assignment_settings"`
}

// Validate validates this domain content update settings v1
func (m *DomainContentUpdateSettingsV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRingAssignmentSettings(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainContentUpdateSettingsV1) validateRingAssignmentSettings(formats strfmt.Registry) error {

	if err := validate.Required("ring_assignment_settings", "body", m.RingAssignmentSettings); err != nil {
		return err
	}

	for i := 0; i < len(m.RingAssignmentSettings); i++ {
		if swag.IsZero(m.RingAssignmentSettings[i]) { // not required
			continue
		}

		if m.RingAssignmentSettings[i] != nil {
			if err := m.RingAssignmentSettings[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ring_assignment_settings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ring_assignment_settings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this domain content update settings v1 based on the context it is used
func (m *DomainContentUpdateSettingsV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRingAssignmentSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainContentUpdateSettingsV1) contextValidateRingAssignmentSettings(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RingAssignmentSettings); i++ {

		if m.RingAssignmentSettings[i] != nil {

			if swag.IsZero(m.RingAssignmentSettings[i]) { // not required
				return nil
			}

			if err := m.RingAssignmentSettings[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ring_assignment_settings" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ring_assignment_settings" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainContentUpdateSettingsV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainContentUpdateSettingsV1) UnmarshalBinary(b []byte) error {
	var res DomainContentUpdateSettingsV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
