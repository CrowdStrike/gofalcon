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

// APIWarningJSON api warning JSON
//
// swagger:model api.WarningJSON
type APIWarningJSON struct {

	// Warnings are categorised to allow you to deal with a whole set of warnings the same way. Other values may be returned if cluster nodes are out of sync, using a newer or older version of LogScale.
	// Required: true
	Category *string `json:"category"`

	// classification
	// Required: true
	Classification *string `json:"classification"`

	// A stable message code that can be used to compare error types or look up error descriptions.
	// Required: true
	Code *string `json:"code"`

	// A Human readable text describing the warning.
	// Required: true
	Message *string `json:"message"`
}

// Validate validates this api warning JSON
func (m *APIWarningJSON) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCategory(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClassification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMessage(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIWarningJSON) validateCategory(formats strfmt.Registry) error {

	if err := validate.Required("category", "body", m.Category); err != nil {
		return err
	}

	return nil
}

func (m *APIWarningJSON) validateClassification(formats strfmt.Registry) error {

	if err := validate.Required("classification", "body", m.Classification); err != nil {
		return err
	}

	return nil
}

func (m *APIWarningJSON) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	return nil
}

func (m *APIWarningJSON) validateMessage(formats strfmt.Registry) error {

	if err := validate.Required("message", "body", m.Message); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this api warning JSON based on context it is used
func (m *APIWarningJSON) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIWarningJSON) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIWarningJSON) UnmarshalBinary(b []byte) error {
	var res APIWarningJSON
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
