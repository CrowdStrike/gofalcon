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

// DomainOCICreateResponse domain o c i create response
//
// swagger:model domain.OCICreateResponse
type DomainOCICreateResponse struct {

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// OCI provided unique identifier for the account.
	// Required: true
	TenancyOcid *string `json:"tenancy_ocid"`
}

// Validate validates this domain o c i create response
func (m *DomainOCICreateResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenancyOcid(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainOCICreateResponse) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *DomainOCICreateResponse) validateTenancyOcid(formats strfmt.Registry) error {

	if err := validate.Required("tenancy_ocid", "body", m.TenancyOcid); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain o c i create response based on context it is used
func (m *DomainOCICreateResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainOCICreateResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainOCICreateResponse) UnmarshalBinary(b []byte) error {
	var res DomainOCICreateResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
