// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DevicecontentContentCategory devicecontent content category
//
// swagger:model devicecontent.ContentCategory
type DevicecontentContentCategory struct {

	// last update
	LastUpdate string `json:"last_update,omitempty"`
}

// Validate validates this devicecontent content category
func (m *DevicecontentContentCategory) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this devicecontent content category based on context it is used
func (m *DevicecontentContentCategory) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DevicecontentContentCategory) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DevicecontentContentCategory) UnmarshalBinary(b []byte) error {
	var res DevicecontentContentCategory
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
