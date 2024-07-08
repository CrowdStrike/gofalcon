// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesGetServicesRelatedEntityFilters types get services related entity filters
//
// swagger:model types.GetServicesRelatedEntityFilters
type TypesGetServicesRelatedEntityFilters struct {

	// include du services
	IncludeDuServices bool `json:"include_du_services,omitempty"`

	// only du types
	OnlyDuTypes bool `json:"only_du_types,omitempty"`

	// only get brokers
	OnlyGetBrokers bool `json:"only_get_brokers,omitempty"`
}

// Validate validates this types get services related entity filters
func (m *TypesGetServicesRelatedEntityFilters) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types get services related entity filters based on context it is used
func (m *TypesGetServicesRelatedEntityFilters) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesGetServicesRelatedEntityFilters) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesGetServicesRelatedEntityFilters) UnmarshalBinary(b []byte) error {
	var res TypesGetServicesRelatedEntityFilters
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
