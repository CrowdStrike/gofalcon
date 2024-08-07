// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesPaginate types paginate
//
// swagger:model types.Paginate
type TypesPaginate struct {

	// direction
	Direction string `json:"direction,omitempty"`

	// limit
	Limit int64 `json:"limit,omitempty"`

	// offset
	Offset int64 `json:"offset,omitempty"`

	// order by
	OrderBy []string `json:"orderBy"`
}

// Validate validates this types paginate
func (m *TypesPaginate) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types paginate based on context it is used
func (m *TypesPaginate) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesPaginate) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesPaginate) UnmarshalBinary(b []byte) error {
	var res TypesPaginate
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
