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

// APIRuleSearchV1 api rule search v1
//
// swagger:model api.RuleSearchV1
type APIRuleSearchV1 struct {

	// filter
	// Required: true
	Filter *string `json:"filter"`

	// lookback
	// Required: true
	Lookback *string `json:"lookback"`

	// outcome
	// Required: true
	Outcome *string `json:"outcome"`

	// trigger mode
	// Required: true
	TriggerMode *string `json:"trigger_mode"`

	// use ingest time
	UseIngestTime bool `json:"use_ingest_time,omitempty"`
}

// Validate validates this api rule search v1
func (m *APIRuleSearchV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFilter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLookback(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOutcome(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTriggerMode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIRuleSearchV1) validateFilter(formats strfmt.Registry) error {

	if err := validate.Required("filter", "body", m.Filter); err != nil {
		return err
	}

	return nil
}

func (m *APIRuleSearchV1) validateLookback(formats strfmt.Registry) error {

	if err := validate.Required("lookback", "body", m.Lookback); err != nil {
		return err
	}

	return nil
}

func (m *APIRuleSearchV1) validateOutcome(formats strfmt.Registry) error {

	if err := validate.Required("outcome", "body", m.Outcome); err != nil {
		return err
	}

	return nil
}

func (m *APIRuleSearchV1) validateTriggerMode(formats strfmt.Registry) error {

	if err := validate.Required("trigger_mode", "body", m.TriggerMode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this api rule search v1 based on context it is used
func (m *APIRuleSearchV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIRuleSearchV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIRuleSearchV1) UnmarshalBinary(b []byte) error {
	var res APIRuleSearchV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
