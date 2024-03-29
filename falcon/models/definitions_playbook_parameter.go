// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DefinitionsPlaybookParameter definitions playbook parameter
//
// swagger:model definitions.PlaybookParameter
type DefinitionsPlaybookParameter struct {

	// id of the node in the model where the parameter needs to be applied
	// Required: true
	NodeID *string `json:"node_id"`

	// list of properties that need to be parameterized
	// Required: true
	Properties []*DefinitionsParameterProperty `json:"properties"`
}

// Validate validates this definitions playbook parameter
func (m *DefinitionsPlaybookParameter) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNodeID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProperties(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DefinitionsPlaybookParameter) validateNodeID(formats strfmt.Registry) error {

	if err := validate.Required("node_id", "body", m.NodeID); err != nil {
		return err
	}

	return nil
}

func (m *DefinitionsPlaybookParameter) validateProperties(formats strfmt.Registry) error {

	if err := validate.Required("properties", "body", m.Properties); err != nil {
		return err
	}

	for i := 0; i < len(m.Properties); i++ {
		if swag.IsZero(m.Properties[i]) { // not required
			continue
		}

		if m.Properties[i] != nil {
			if err := m.Properties[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("properties" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("properties" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this definitions playbook parameter based on the context it is used
func (m *DefinitionsPlaybookParameter) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateProperties(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DefinitionsPlaybookParameter) contextValidateProperties(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Properties); i++ {

		if m.Properties[i] != nil {

			if swag.IsZero(m.Properties[i]) { // not required
				return nil
			}

			if err := m.Properties[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("properties" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("properties" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DefinitionsPlaybookParameter) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DefinitionsPlaybookParameter) UnmarshalBinary(b []byte) error {
	var res DefinitionsPlaybookParameter
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
