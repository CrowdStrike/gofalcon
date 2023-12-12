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

// ModelsContainerCoverage models container coverage
//
// swagger:model models.ContainerCoverage
type ModelsContainerCoverage struct {

	// managed
	// Required: true
	Managed *int64 `json:"managed"`

	// unmanaged
	// Required: true
	Unmanaged *int64 `json:"unmanaged"`
}

// Validate validates this models container coverage
func (m *ModelsContainerCoverage) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateManaged(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUnmanaged(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsContainerCoverage) validateManaged(formats strfmt.Registry) error {

	if err := validate.Required("managed", "body", m.Managed); err != nil {
		return err
	}

	return nil
}

func (m *ModelsContainerCoverage) validateUnmanaged(formats strfmt.Registry) error {

	if err := validate.Required("unmanaged", "body", m.Unmanaged); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models container coverage based on context it is used
func (m *ModelsContainerCoverage) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsContainerCoverage) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsContainerCoverage) UnmarshalBinary(b []byte) error {
	var res ModelsContainerCoverage
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
