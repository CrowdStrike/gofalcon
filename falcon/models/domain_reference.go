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

// DomainReference domain reference
//
// swagger:model domain.Reference
type DomainReference struct {

	// tags
	// Required: true
	Tags []string `json:"Tags"`

	// URL
	// Required: true
	URL *string `json:"URL"`
}

// Validate validates this domain reference
func (m *DomainReference) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateURL(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainReference) validateTags(formats strfmt.Registry) error {

	if err := validate.Required("Tags", "body", m.Tags); err != nil {
		return err
	}

	return nil
}

func (m *DomainReference) validateURL(formats strfmt.Registry) error {

	if err := validate.Required("URL", "body", m.URL); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain reference based on context it is used
func (m *DomainReference) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainReference) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainReference) UnmarshalBinary(b []byte) error {
	var res DomainReference
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
