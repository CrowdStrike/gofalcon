// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ChangesPolicyRule changes policy rule
//
// swagger:model changes.PolicyRule
type ChangesPolicyRule struct {

	// base path
	BasePath string `json:"base_path,omitempty"`
}

// Validate validates this changes policy rule
func (m *ChangesPolicyRule) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this changes policy rule based on context it is used
func (m *ChangesPolicyRule) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ChangesPolicyRule) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ChangesPolicyRule) UnmarshalBinary(b []byte) error {
	var res ChangesPolicyRule
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
