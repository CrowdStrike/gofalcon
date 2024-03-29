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

// JsonschemaSchema jsonschema schema
//
// swagger:model jsonschema.Schema
type JsonschemaSchema struct {

	// sub schema
	// Required: true
	SubSchema *JsonschemaSubSchema `json:"SubSchema"`

	// definitions
	Definitions map[string]JsonschemaSubSchema `json:"definitions,omitempty"`
}

// Validate validates this jsonschema schema
func (m *JsonschemaSchema) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSubSchema(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefinitions(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JsonschemaSchema) validateSubSchema(formats strfmt.Registry) error {

	if err := validate.Required("SubSchema", "body", m.SubSchema); err != nil {
		return err
	}

	if m.SubSchema != nil {
		if err := m.SubSchema.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubSchema")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubSchema")
			}
			return err
		}
	}

	return nil
}

func (m *JsonschemaSchema) validateDefinitions(formats strfmt.Registry) error {
	if swag.IsZero(m.Definitions) { // not required
		return nil
	}

	for k := range m.Definitions {

		if err := validate.Required("definitions"+"."+k, "body", m.Definitions[k]); err != nil {
			return err
		}
		if val, ok := m.Definitions[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("definitions" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("definitions" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this jsonschema schema based on the context it is used
func (m *JsonschemaSchema) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSubSchema(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDefinitions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JsonschemaSchema) contextValidateSubSchema(ctx context.Context, formats strfmt.Registry) error {

	if m.SubSchema != nil {

		if err := m.SubSchema.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SubSchema")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SubSchema")
			}
			return err
		}
	}

	return nil
}

func (m *JsonschemaSchema) contextValidateDefinitions(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.Definitions {

		if val, ok := m.Definitions[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *JsonschemaSchema) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JsonschemaSchema) UnmarshalBinary(b []byte) error {
	var res JsonschemaSchema
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
