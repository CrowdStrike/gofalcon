// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ChangesPolicy changes policy
//
// swagger:model changes.Policy
type ChangesPolicy struct {

	// name
	Name string `json:"name,omitempty"`

	// rule group
	RuleGroup *ChangesPolicyRuleGroup `json:"rule_group,omitempty"`
}

// Validate validates this changes policy
func (m *ChangesPolicy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRuleGroup(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ChangesPolicy) validateRuleGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.RuleGroup) { // not required
		return nil
	}

	if m.RuleGroup != nil {
		if err := m.RuleGroup.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rule_group")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rule_group")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this changes policy based on the context it is used
func (m *ChangesPolicy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRuleGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ChangesPolicy) contextValidateRuleGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.RuleGroup != nil {

		if swag.IsZero(m.RuleGroup) { // not required
			return nil
		}

		if err := m.RuleGroup.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rule_group")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rule_group")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ChangesPolicy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ChangesPolicy) UnmarshalBinary(b []byte) error {
	var res ChangesPolicy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
