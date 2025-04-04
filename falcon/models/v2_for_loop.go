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

// V2ForLoop v2 for loop
//
// swagger:model v2.ForLoop
type V2ForLoop struct {

	// cel condition
	CelCondition string `json:"cel_condition,omitempty"`

	// condition
	Condition string `json:"condition,omitempty"`

	// condition display
	ConditionDisplay []string `json:"condition_display"`

	// continue on partial execution
	// Required: true
	ContinueOnPartialExecution *bool `json:"continue_on_partial_execution"`

	// input
	// Required: true
	Input *string `json:"input"`

	// max execution seconds
	MaxExecutionSeconds int32 `json:"max_execution_seconds,omitempty"`

	// max iteration count
	MaxIterationCount int32 `json:"max_iteration_count,omitempty"`

	// sequential
	Sequential bool `json:"sequential,omitempty"`
}

// Validate validates this v2 for loop
func (m *V2ForLoop) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContinueOnPartialExecution(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInput(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V2ForLoop) validateContinueOnPartialExecution(formats strfmt.Registry) error {

	if err := validate.Required("continue_on_partial_execution", "body", m.ContinueOnPartialExecution); err != nil {
		return err
	}

	return nil
}

func (m *V2ForLoop) validateInput(formats strfmt.Registry) error {

	if err := validate.Required("input", "body", m.Input); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this v2 for loop based on context it is used
func (m *V2ForLoop) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V2ForLoop) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V2ForLoop) UnmarshalBinary(b []byte) error {
	var res V2ForLoop
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
