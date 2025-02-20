// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// JsonschemaPivot jsonschema pivot
//
// swagger:model jsonschema.Pivot
type JsonschemaPivot struct {

	// case sensitive
	CaseSensitive bool `json:"caseSensitive,omitempty"`

	// entity
	Entity string `json:"entity,omitempty"`

	// entity on load
	EntityOnLoad string `json:"entityOnLoad,omitempty"`

	// entity value
	EntityValue string `json:"entityValue,omitempty"`

	// query string
	QueryString string `json:"queryString,omitempty"`

	// query string on load
	QueryStringOnLoad string `json:"queryStringOnLoad,omitempty"`

	// searchable
	Searchable bool `json:"searchable,omitempty"`

	// sort by display
	SortByDisplay bool `json:"sortByDisplay,omitempty"`

	// sort by value
	SortByValue bool `json:"sortByValue,omitempty"`

	// sort desc
	SortDesc bool `json:"sortDesc,omitempty"`

	// strict
	Strict bool `json:"strict,omitempty"`
}

// Validate validates this jsonschema pivot
func (m *JsonschemaPivot) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this jsonschema pivot based on context it is used
func (m *JsonschemaPivot) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *JsonschemaPivot) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JsonschemaPivot) UnmarshalBinary(b []byte) error {
	var res JsonschemaPivot
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
