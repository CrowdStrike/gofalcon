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

// RegistrationIOMEventIDResponseMeta registration i o m event ID response meta
//
// swagger:model registration.IOMEventIDResponseMeta
type RegistrationIOMEventIDResponseMeta struct {

	// pagination
	// Required: true
	Pagination *RegistrationNextTokenPagination `json:"pagination"`

	// powered by
	// Required: true
	PoweredBy *string `json:"powered_by"`

	// query time
	// Required: true
	QueryTime *float64 `json:"query_time"`

	// trace id
	// Required: true
	TraceID *string `json:"trace_id"`
}

// Validate validates this registration i o m event ID response meta
func (m *RegistrationIOMEventIDResponseMeta) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePagination(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePoweredBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQueryTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTraceID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationIOMEventIDResponseMeta) validatePagination(formats strfmt.Registry) error {

	if err := validate.Required("pagination", "body", m.Pagination); err != nil {
		return err
	}

	if m.Pagination != nil {
		if err := m.Pagination.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

func (m *RegistrationIOMEventIDResponseMeta) validatePoweredBy(formats strfmt.Registry) error {

	if err := validate.Required("powered_by", "body", m.PoweredBy); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventIDResponseMeta) validateQueryTime(formats strfmt.Registry) error {

	if err := validate.Required("query_time", "body", m.QueryTime); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventIDResponseMeta) validateTraceID(formats strfmt.Registry) error {

	if err := validate.Required("trace_id", "body", m.TraceID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this registration i o m event ID response meta based on the context it is used
func (m *RegistrationIOMEventIDResponseMeta) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePagination(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationIOMEventIDResponseMeta) contextValidatePagination(ctx context.Context, formats strfmt.Registry) error {

	if m.Pagination != nil {

		if err := m.Pagination.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RegistrationIOMEventIDResponseMeta) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegistrationIOMEventIDResponseMeta) UnmarshalBinary(b []byte) error {
	var res RegistrationIOMEventIDResponseMeta
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
