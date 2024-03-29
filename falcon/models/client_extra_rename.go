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

// ClientExtraRename client extra rename
//
// swagger:model client.ExtraRename
type ClientExtraRename struct {

	// as
	// Required: true
	As *string `json:"as"`

	// field
	// Required: true
	Field *string `json:"field"`
}

// Validate validates this client extra rename
func (m *ClientExtraRename) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateField(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ClientExtraRename) validateAs(formats strfmt.Registry) error {

	if err := validate.Required("as", "body", m.As); err != nil {
		return err
	}

	return nil
}

func (m *ClientExtraRename) validateField(formats strfmt.Registry) error {

	if err := validate.Required("field", "body", m.Field); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this client extra rename based on context it is used
func (m *ClientExtraRename) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ClientExtraRename) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClientExtraRename) UnmarshalBinary(b []byte) error {
	var res ClientExtraRename
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
