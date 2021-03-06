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

// DomainSPAPIQueryVulnerabilitiesPaging domain s p API query vulnerabilities paging
//
// swagger:model domain.SPAPIQueryVulnerabilitiesPaging
type DomainSPAPIQueryVulnerabilitiesPaging struct {

	// after
	// Required: true
	After *string `json:"after"`

	// limit
	// Required: true
	Limit *int32 `json:"limit"`

	// total
	// Required: true
	Total *int64 `json:"total"`
}

// Validate validates this domain s p API query vulnerabilities paging
func (m *DomainSPAPIQueryVulnerabilitiesPaging) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAfter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLimit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotal(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainSPAPIQueryVulnerabilitiesPaging) validateAfter(formats strfmt.Registry) error {

	if err := validate.Required("after", "body", m.After); err != nil {
		return err
	}

	return nil
}

func (m *DomainSPAPIQueryVulnerabilitiesPaging) validateLimit(formats strfmt.Registry) error {

	if err := validate.Required("limit", "body", m.Limit); err != nil {
		return err
	}

	return nil
}

func (m *DomainSPAPIQueryVulnerabilitiesPaging) validateTotal(formats strfmt.Registry) error {

	if err := validate.Required("total", "body", m.Total); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain s p API query vulnerabilities paging based on context it is used
func (m *DomainSPAPIQueryVulnerabilitiesPaging) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainSPAPIQueryVulnerabilitiesPaging) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainSPAPIQueryVulnerabilitiesPaging) UnmarshalBinary(b []byte) error {
	var res DomainSPAPIQueryVulnerabilitiesPaging
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
