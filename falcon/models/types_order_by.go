// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesOrderBy types order by
//
// swagger:model types.OrderBy
type TypesOrderBy struct {

	// by field
	ByField string `json:"by_field,omitempty"`

	// direction
	Direction int32 `json:"direction,omitempty"`
}

// Validate validates this types order by
func (m *TypesOrderBy) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types order by based on context it is used
func (m *TypesOrderBy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesOrderBy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesOrderBy) UnmarshalBinary(b []byte) error {
	var res TypesOrderBy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
