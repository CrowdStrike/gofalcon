// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesDeploymentUnitService types deployment unit service
//
// swagger:model types.DeploymentUnitService
type TypesDeploymentUnitService struct {

	// id
	ID int64 `json:"id,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// persistent signature
	PersistentSignature string `json:"persistentSignature,omitempty"`
}

// Validate validates this types deployment unit service
func (m *TypesDeploymentUnitService) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types deployment unit service based on context it is used
func (m *TypesDeploymentUnitService) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesDeploymentUnitService) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesDeploymentUnitService) UnmarshalBinary(b []byte) error {
	var res TypesDeploymentUnitService
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
