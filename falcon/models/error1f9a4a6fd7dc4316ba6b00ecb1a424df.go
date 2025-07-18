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

// Error1f9a4a6fd7dc4316ba6b00ecb1a424df error 1f9a4a6fd7dc4316ba6b00ecb1a424df
//
// swagger:model Error_1f9a4a6fd7dc4316ba6b00ecb1a424df
type Error1f9a4a6fd7dc4316ba6b00ecb1a424df struct {

	// Code
	// Required: true
	Code *string `json:"code"`

	// Message
	// Min Length: 1
	Message *string `json:"message,omitempty"`
}

// Validate validates this error 1f9a4a6fd7dc4316ba6b00ecb1a424df
func (m *Error1f9a4a6fd7dc4316ba6b00ecb1a424df) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMessage(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Error1f9a4a6fd7dc4316ba6b00ecb1a424df) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *Error1f9a4a6fd7dc4316ba6b00ecb1a424df) validateMessage(formats strfmt.Registry) error {
	if swag.IsZero(m.Message) { // not required
		return nil
	}

	if err := validate.MinLength("message", "body", *m.Message, 1); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this error 1f9a4a6fd7dc4316ba6b00ecb1a424df based on context it is used
func (m *Error1f9a4a6fd7dc4316ba6b00ecb1a424df) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Error1f9a4a6fd7dc4316ba6b00ecb1a424df) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Error1f9a4a6fd7dc4316ba6b00ecb1a424df) UnmarshalBinary(b []byte) error {
	var res Error1f9a4a6fd7dc4316ba6b00ecb1a424df
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
