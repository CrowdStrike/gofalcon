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

// APIPostEnrollmentDetailsV4 api post enrollment details v4
//
// swagger:model api.postEnrollmentDetailsV4
type APIPostEnrollmentDetailsV4 struct {

	// email addresses
	// Required: true
	EmailAddresses []string `json:"email_addresses"`

	// enrollment type
	// Required: true
	EnrollmentType *string `json:"enrollment_type"`

	// expires at
	// Required: true
	// Format: date-time
	ExpiresAt *strfmt.DateTime `json:"expires_at"`
}

// Validate validates this api post enrollment details v4
func (m *APIPostEnrollmentDetailsV4) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmailAddresses(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnrollmentType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIPostEnrollmentDetailsV4) validateEmailAddresses(formats strfmt.Registry) error {

	if err := validate.Required("email_addresses", "body", m.EmailAddresses); err != nil {
		return err
	}

	return nil
}

func (m *APIPostEnrollmentDetailsV4) validateEnrollmentType(formats strfmt.Registry) error {

	if err := validate.Required("enrollment_type", "body", m.EnrollmentType); err != nil {
		return err
	}

	return nil
}

func (m *APIPostEnrollmentDetailsV4) validateExpiresAt(formats strfmt.Registry) error {

	if err := validate.Required("expires_at", "body", m.ExpiresAt); err != nil {
		return err
	}

	if err := validate.FormatOf("expires_at", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this api post enrollment details v4 based on context it is used
func (m *APIPostEnrollmentDetailsV4) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIPostEnrollmentDetailsV4) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIPostEnrollmentDetailsV4) UnmarshalBinary(b []byte) error {
	var res APIPostEnrollmentDetailsV4
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
