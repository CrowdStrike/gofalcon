// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// APIExposedDataRecordLocationV1 api exposed data record location v1
//
// swagger:model api.ExposedDataRecordLocationV1
type APIExposedDataRecordLocationV1 struct {

	// City name
	City string `json:"city,omitempty"`

	// The country code
	CountryCode string `json:"country_code,omitempty"`

	// Federal Administrative Region
	FederalAdminRegion string `json:"federal_admin_region,omitempty"`

	// Federal District
	FederalDistrict string `json:"federal_district,omitempty"`

	// The postal code
	PostalCode string `json:"postal_code,omitempty"`

	// State name
	State string `json:"state,omitempty"`
}

// Validate validates this api exposed data record location v1
func (m *APIExposedDataRecordLocationV1) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this api exposed data record location v1 based on context it is used
func (m *APIExposedDataRecordLocationV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIExposedDataRecordLocationV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIExposedDataRecordLocationV1) UnmarshalBinary(b []byte) error {
	var res APIExposedDataRecordLocationV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
