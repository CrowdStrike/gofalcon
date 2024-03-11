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

// DefinitionsDefinitionExt definitions definition ext
//
// swagger:model definitions.DefinitionExt
type DefinitionsDefinitionExt struct {

	// definition
	// Required: true
	Definition *V2Definition `json:"Definition"`

	// Indicates whether the workflow is enabled and active or not.
	// Required: true
	Enabled *bool `json:"enabled"`

	// Unique identifier for the trigger.
	// Required: true
	ID *string `json:"id"`

	// Timestamp of when this version of the workflow was created.
	// Required: true
	// Format: date-time
	LastModifiedTimestamp *strfmt.DateTime `json:"last_modified_timestamp"`

	// Version of the workflow. A given definition ID can have many versions. Each time an update is applied a new version is generated.
	// Required: true
	Version *int32 `json:"version"`
}

// Validate validates this definitions definition ext
func (m *DefinitionsDefinitionExt) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDefinition(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastModifiedTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVersion(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DefinitionsDefinitionExt) validateDefinition(formats strfmt.Registry) error {

	if err := validate.Required("Definition", "body", m.Definition); err != nil {
		return err
	}

	if m.Definition != nil {
		if err := m.Definition.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Definition")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Definition")
			}
			return err
		}
	}

	return nil
}

func (m *DefinitionsDefinitionExt) validateEnabled(formats strfmt.Registry) error {

	if err := validate.Required("enabled", "body", m.Enabled); err != nil {
		return err
	}

	return nil
}

func (m *DefinitionsDefinitionExt) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DefinitionsDefinitionExt) validateLastModifiedTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("last_modified_timestamp", "body", m.LastModifiedTimestamp); err != nil {
		return err
	}

	if err := validate.FormatOf("last_modified_timestamp", "body", "date-time", m.LastModifiedTimestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DefinitionsDefinitionExt) validateVersion(formats strfmt.Registry) error {

	if err := validate.Required("version", "body", m.Version); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this definitions definition ext based on the context it is used
func (m *DefinitionsDefinitionExt) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDefinition(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DefinitionsDefinitionExt) contextValidateDefinition(ctx context.Context, formats strfmt.Registry) error {

	if m.Definition != nil {

		if err := m.Definition.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Definition")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Definition")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DefinitionsDefinitionExt) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DefinitionsDefinitionExt) UnmarshalBinary(b []byte) error {
	var res DefinitionsDefinitionExt
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}