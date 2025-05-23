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

// AzureResourcePermission azure resource permission
//
// swagger:model azure.ResourcePermission
type AzureResourcePermission struct {

	// name
	Name string `json:"name,omitempty"`

	// resource id
	ResourceID string `json:"resource_id,omitempty"`

	// role id
	RoleID string `json:"role_id,omitempty"`

	// status
	// Required: true
	Status *string `json:"status"`

	// type
	Type string `json:"type,omitempty"`
}

// Validate validates this azure resource permission
func (m *AzureResourcePermission) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AzureResourcePermission) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this azure resource permission based on context it is used
func (m *AzureResourcePermission) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *AzureResourcePermission) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AzureResourcePermission) UnmarshalBinary(b []byte) error {
	var res AzureResourcePermission
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
