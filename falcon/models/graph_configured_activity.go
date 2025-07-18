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

// GraphConfiguredActivity graph configured activity
//
// swagger:model graph.ConfiguredActivity
type GraphConfiguredActivity struct {

	// The class of activity. If undefined it is an ActivityClassDefault
	Class string `json:"class,omitempty"`

	// References to the incoming and outgoing sequence flows attached to the activity.
	// Required: true
	Flows *Flows `json:"flows"`

	// The unique identifier of the selected activity that is being configured.
	// Required: true
	ID *string `json:"id"`

	// Inline activity configuration required by an inline action.
	InlineConfiguration *GraphInlineActivityConfig `json:"inline_configuration,omitempty"`

	// Maximum seconds to wait for an async process to finish. Overrides default async_max_seconds on Activity seed.
	MaxSeconds string `json:"max_seconds,omitempty"`

	// Optional user provided name for the activity, if not specified a default of the name for that Activity will be used.
	// Required: true
	Name *string `json:"name"`

	// node ID
	// Required: true
	NodeID *string `json:"nodeID"`

	// Dynamic payload providing values needed to configure the activity for execution. The structure of this data is dictated by the JSON Schema defined for the selected Activity.
	// Required: true
	Properties interface{} `json:"properties"`

	// Semantic version constraint of the activity, can be an explicit version or a version constraint. If unspecified the latest activity <= 1.0.0 is used.
	VersionConstraint string `json:"version_constraint,omitempty"`
}

// Validate validates this graph configured activity
func (m *GraphConfiguredActivity) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFlows(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInlineConfiguration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

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

func (m *GraphConfiguredActivity) validateFlows(formats strfmt.Registry) error {

	if err := validate.Required("flows", "body", m.Flows); err != nil {
		return err
	}

	if m.Flows != nil {
		if err := m.Flows.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("flows")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("flows")
			}
			return err
		}
	}

	return nil
}

func (m *GraphConfiguredActivity) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *GraphConfiguredActivity) validateInlineConfiguration(formats strfmt.Registry) error {
	if swag.IsZero(m.InlineConfiguration) { // not required
		return nil
	}

	if m.InlineConfiguration != nil {
		if err := m.InlineConfiguration.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("inline_configuration")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("inline_configuration")
			}
			return err
		}
	}

	return nil
}

func (m *GraphConfiguredActivity) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *GraphConfiguredActivity) validateNodeID(formats strfmt.Registry) error {

	if err := validate.Required("nodeID", "body", m.NodeID); err != nil {
		return err
	}

	return nil
}

func (m *GraphConfiguredActivity) validateProperties(formats strfmt.Registry) error {

	if m.Properties == nil {
		return errors.Required("properties", "body", nil)
	}

	return nil
}

// ContextValidate validate this graph configured activity based on the context it is used
func (m *GraphConfiguredActivity) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFlows(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInlineConfiguration(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GraphConfiguredActivity) contextValidateFlows(ctx context.Context, formats strfmt.Registry) error {

	if m.Flows != nil {

		if err := m.Flows.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("flows")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("flows")
			}
			return err
		}
	}

	return nil
}

func (m *GraphConfiguredActivity) contextValidateInlineConfiguration(ctx context.Context, formats strfmt.Registry) error {

	if m.InlineConfiguration != nil {

		if swag.IsZero(m.InlineConfiguration) { // not required
			return nil
		}

		if err := m.InlineConfiguration.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("inline_configuration")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("inline_configuration")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GraphConfiguredActivity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GraphConfiguredActivity) UnmarshalBinary(b []byte) error {
	var res GraphConfiguredActivity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
