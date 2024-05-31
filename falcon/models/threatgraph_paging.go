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

// ThreatgraphPaging threatgraph paging
//
// swagger:model threatgraph.Paging
type ThreatgraphPaging struct {

	// limit
	// Required: true
	Limit *int32 `json:"limit"`

	// next page
	NextPage string `json:"next_page,omitempty"`

	// offset
	Offset string `json:"offset,omitempty"`
}

// Validate validates this threatgraph paging
func (m *ThreatgraphPaging) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLimit(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ThreatgraphPaging) validateLimit(formats strfmt.Registry) error {

	if err := validate.Required("limit", "body", m.Limit); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this threatgraph paging based on context it is used
func (m *ThreatgraphPaging) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ThreatgraphPaging) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ThreatgraphPaging) UnmarshalBinary(b []byte) error {
	var res ThreatgraphPaging
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
