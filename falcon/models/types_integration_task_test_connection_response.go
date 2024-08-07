// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesIntegrationTaskTestConnectionResponse types integration task test connection response
//
// swagger:model types.IntegrationTaskTestConnectionResponse
type TypesIntegrationTaskTestConnectionResponse struct {

	// action run id
	ActionRunID int64 `json:"action_run_id,omitempty"`
}

// Validate validates this types integration task test connection response
func (m *TypesIntegrationTaskTestConnectionResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types integration task test connection response based on context it is used
func (m *TypesIntegrationTaskTestConnectionResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesIntegrationTaskTestConnectionResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesIntegrationTaskTestConnectionResponse) UnmarshalBinary(b []byte) error {
	var res TypesIntegrationTaskTestConnectionResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
