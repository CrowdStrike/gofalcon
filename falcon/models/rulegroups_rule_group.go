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

// RulegroupsRuleGroup rulegroups rule group
//
// swagger:model rulegroups.RuleGroup
type RulegroupsRuleGroup struct {

	// assigned rules
	AssignedRules []*RulegroupsAssignedRule `json:"assigned_rules"`

	// created by
	CreatedBy string `json:"created_by,omitempty"`

	// created timestamp
	CreatedTimestamp string `json:"created_timestamp,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// id
	// Required: true
	ID *string `json:"id"`

	// modified by
	ModifiedBy string `json:"modified_by,omitempty"`

	// modified timestamp
	ModifiedTimestamp string `json:"modified_timestamp,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// policy assignments
	PolicyAssignments []*RulegroupsPolicyAssignment `json:"policy_assignments"`

	// type
	Type string `json:"type,omitempty"`
}

// Validate validates this rulegroups rule group
func (m *RulegroupsRuleGroup) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAssignedRules(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyAssignments(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RulegroupsRuleGroup) validateAssignedRules(formats strfmt.Registry) error {
	if swag.IsZero(m.AssignedRules) { // not required
		return nil
	}

	for i := 0; i < len(m.AssignedRules); i++ {
		if swag.IsZero(m.AssignedRules[i]) { // not required
			continue
		}

		if m.AssignedRules[i] != nil {
			if err := m.AssignedRules[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("assigned_rules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("assigned_rules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RulegroupsRuleGroup) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *RulegroupsRuleGroup) validatePolicyAssignments(formats strfmt.Registry) error {
	if swag.IsZero(m.PolicyAssignments) { // not required
		return nil
	}

	for i := 0; i < len(m.PolicyAssignments); i++ {
		if swag.IsZero(m.PolicyAssignments[i]) { // not required
			continue
		}

		if m.PolicyAssignments[i] != nil {
			if err := m.PolicyAssignments[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policy_assignments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policy_assignments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this rulegroups rule group based on the context it is used
func (m *RulegroupsRuleGroup) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAssignedRules(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePolicyAssignments(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RulegroupsRuleGroup) contextValidateAssignedRules(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AssignedRules); i++ {

		if m.AssignedRules[i] != nil {

			if swag.IsZero(m.AssignedRules[i]) { // not required
				return nil
			}

			if err := m.AssignedRules[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("assigned_rules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("assigned_rules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RulegroupsRuleGroup) contextValidatePolicyAssignments(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.PolicyAssignments); i++ {

		if m.PolicyAssignments[i] != nil {

			if swag.IsZero(m.PolicyAssignments[i]) { // not required
				return nil
			}

			if err := m.PolicyAssignments[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policy_assignments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policy_assignments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *RulegroupsRuleGroup) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RulegroupsRuleGroup) UnmarshalBinary(b []byte) error {
	var res RulegroupsRuleGroup
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
