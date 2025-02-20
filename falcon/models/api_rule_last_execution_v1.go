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

// APIRuleLastExecutionV1 api rule last execution v1
//
// swagger:model api.RuleLastExecutionV1
type APIRuleLastExecutionV1 struct {

	// result metadata
	ResultMetadata *APIRuleResultMetadataV1 `json:"result_metadata,omitempty"`

	// status display
	StatusDisplay string `json:"status_display,omitempty"`
}

// Validate validates this api rule last execution v1
func (m *APIRuleLastExecutionV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateResultMetadata(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIRuleLastExecutionV1) validateResultMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.ResultMetadata) { // not required
		return nil
	}

	if m.ResultMetadata != nil {
		if err := m.ResultMetadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result_metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("result_metadata")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this api rule last execution v1 based on the context it is used
func (m *APIRuleLastExecutionV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateResultMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIRuleLastExecutionV1) contextValidateResultMetadata(ctx context.Context, formats strfmt.Registry) error {

	if m.ResultMetadata != nil {

		if swag.IsZero(m.ResultMetadata) { // not required
			return nil
		}

		if err := m.ResultMetadata.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result_metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("result_metadata")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *APIRuleLastExecutionV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIRuleLastExecutionV1) UnmarshalBinary(b []byte) error {
	var res APIRuleLastExecutionV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
