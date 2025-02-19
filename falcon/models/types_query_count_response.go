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

// TypesQueryCountResponse types query count response
//
// swagger:model types.QueryCountResponse
type TypesQueryCountResponse struct {

	// count
	// Required: true
	Count *int64 `json:"count"`

	// result type
	// Required: true
	ResultType *string `json:"resultType"`
}

// Validate validates this types query count response
func (m *TypesQueryCountResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResultType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesQueryCountResponse) validateCount(formats strfmt.Registry) error {

	if err := validate.Required("count", "body", m.Count); err != nil {
		return err
	}

	return nil
}

func (m *TypesQueryCountResponse) validateResultType(formats strfmt.Registry) error {

	if err := validate.Required("resultType", "body", m.ResultType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this types query count response based on context it is used
func (m *TypesQueryCountResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesQueryCountResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesQueryCountResponse) UnmarshalBinary(b []byte) error {
	var res TypesQueryCountResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
