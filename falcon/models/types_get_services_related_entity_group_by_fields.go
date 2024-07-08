// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesGetServicesRelatedEntityGroupByFields types get services related entity group by fields
//
// swagger:model types.GetServicesRelatedEntityGroupByFields
type TypesGetServicesRelatedEntityGroupByFields struct {

	// fields
	Fields []string `json:"fields"`
}

// Validate validates this types get services related entity group by fields
func (m *TypesGetServicesRelatedEntityGroupByFields) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types get services related entity group by fields based on context it is used
func (m *TypesGetServicesRelatedEntityGroupByFields) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesGetServicesRelatedEntityGroupByFields) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesGetServicesRelatedEntityGroupByFields) UnmarshalBinary(b []byte) error {
	var res TypesGetServicesRelatedEntityGroupByFields
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
