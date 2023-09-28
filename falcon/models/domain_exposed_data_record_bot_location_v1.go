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

// DomainExposedDataRecordBotLocationV1 domain exposed data record bot location v1
//
// swagger:model domain.ExposedDataRecordBotLocationV1
type DomainExposedDataRecordBotLocationV1 struct {

	// country
	// Required: true
	Country *string `json:"country"`

	// zip code
	// Required: true
	ZipCode *string `json:"zip_code"`
}

// Validate validates this domain exposed data record bot location v1
func (m *DomainExposedDataRecordBotLocationV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCountry(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateZipCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExposedDataRecordBotLocationV1) validateCountry(formats strfmt.Registry) error {

	if err := validate.Required("country", "body", m.Country); err != nil {
		return err
	}

	return nil
}

func (m *DomainExposedDataRecordBotLocationV1) validateZipCode(formats strfmt.Registry) error {

	if err := validate.Required("zip_code", "body", m.ZipCode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain exposed data record bot location v1 based on context it is used
func (m *DomainExposedDataRecordBotLocationV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainExposedDataRecordBotLocationV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainExposedDataRecordBotLocationV1) UnmarshalBinary(b []byte) error {
	var res DomainExposedDataRecordBotLocationV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
