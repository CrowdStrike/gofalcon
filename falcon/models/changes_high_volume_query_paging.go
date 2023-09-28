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

// ChangesHighVolumeQueryPaging changes high volume query paging
//
// swagger:model changes.HighVolumeQueryPaging
type ChangesHighVolumeQueryPaging struct {

	// after
	// Required: true
	After *string `json:"after"`

	// limit
	// Required: true
	Limit *int32 `json:"limit"`

	// total
	// Required: true
	Total *int64 `json:"total"`
}

// Validate validates this changes high volume query paging
func (m *ChangesHighVolumeQueryPaging) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAfter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLimit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotal(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ChangesHighVolumeQueryPaging) validateAfter(formats strfmt.Registry) error {

	if err := validate.Required("after", "body", m.After); err != nil {
		return err
	}

	return nil
}

func (m *ChangesHighVolumeQueryPaging) validateLimit(formats strfmt.Registry) error {

	if err := validate.Required("limit", "body", m.Limit); err != nil {
		return err
	}

	return nil
}

func (m *ChangesHighVolumeQueryPaging) validateTotal(formats strfmt.Registry) error {

	if err := validate.Required("total", "body", m.Total); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this changes high volume query paging based on context it is used
func (m *ChangesHighVolumeQueryPaging) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ChangesHighVolumeQueryPaging) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ChangesHighVolumeQueryPaging) UnmarshalBinary(b []byte) error {
	var res ChangesHighVolumeQueryPaging
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
