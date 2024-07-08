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

// ModelsRulesWithNonCompliantAssets models rules with non compliant assets
//
// swagger:model models.RulesWithNonCompliantAssets
type ModelsRulesWithNonCompliantAssets struct {

	// not applicable filters
	// Required: true
	NotApplicableFilters *string `json:"not_applicable_filters"`

	// rules
	// Required: true
	Rules []*ModelsRuleWithNonCompliantAssets `json:"rules"`
}

// Validate validates this models rules with non compliant assets
func (m *ModelsRulesWithNonCompliantAssets) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNotApplicableFilters(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRules(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsRulesWithNonCompliantAssets) validateNotApplicableFilters(formats strfmt.Registry) error {

	if err := validate.Required("not_applicable_filters", "body", m.NotApplicableFilters); err != nil {
		return err
	}

	return nil
}

func (m *ModelsRulesWithNonCompliantAssets) validateRules(formats strfmt.Registry) error {

	if err := validate.Required("rules", "body", m.Rules); err != nil {
		return err
	}

	for i := 0; i < len(m.Rules); i++ {
		if swag.IsZero(m.Rules[i]) { // not required
			continue
		}

		if m.Rules[i] != nil {
			if err := m.Rules[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this models rules with non compliant assets based on the context it is used
func (m *ModelsRulesWithNonCompliantAssets) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRules(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsRulesWithNonCompliantAssets) contextValidateRules(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Rules); i++ {

		if m.Rules[i] != nil {

			if swag.IsZero(m.Rules[i]) { // not required
				return nil
			}

			if err := m.Rules[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModelsRulesWithNonCompliantAssets) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsRulesWithNonCompliantAssets) UnmarshalBinary(b []byte) error {
	var res ModelsRulesWithNonCompliantAssets
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
