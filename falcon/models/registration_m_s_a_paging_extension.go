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

// RegistrationMSAPagingExtension registration m s a paging extension
//
// swagger:model registration.MSAPagingExtension
type RegistrationMSAPagingExtension struct {

	// paging
	// Required: true
	Paging *MsaPaging `json:"Paging"`

	// next token
	NextToken string `json:"next_token,omitempty"`
}

// Validate validates this registration m s a paging extension
func (m *RegistrationMSAPagingExtension) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePaging(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationMSAPagingExtension) validatePaging(formats strfmt.Registry) error {

	if err := validate.Required("Paging", "body", m.Paging); err != nil {
		return err
	}

	if m.Paging != nil {
		if err := m.Paging.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Paging")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Paging")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this registration m s a paging extension based on the context it is used
func (m *RegistrationMSAPagingExtension) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePaging(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationMSAPagingExtension) contextValidatePaging(ctx context.Context, formats strfmt.Registry) error {

	if m.Paging != nil {

		if err := m.Paging.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Paging")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Paging")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RegistrationMSAPagingExtension) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegistrationMSAPagingExtension) UnmarshalBinary(b []byte) error {
	var res RegistrationMSAPagingExtension
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
