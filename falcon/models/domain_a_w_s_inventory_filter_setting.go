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

// DomainAWSInventoryFilterSetting domain a w s inventory filter setting
//
// swagger:model domain.AWSInventoryFilterSetting
type DomainAWSInventoryFilterSetting struct {

	// account id
	// Required: true
	AccountID *string `json:"account_id"`

	// regions
	// Required: true
	Regions []string `json:"regions"`

	// service
	// Required: true
	Service *string `json:"service"`
}

// Validate validates this domain a w s inventory filter setting
func (m *DomainAWSInventoryFilterSetting) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRegions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainAWSInventoryFilterSetting) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("account_id", "body", m.AccountID); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSInventoryFilterSetting) validateRegions(formats strfmt.Registry) error {

	if err := validate.Required("regions", "body", m.Regions); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSInventoryFilterSetting) validateService(formats strfmt.Registry) error {

	if err := validate.Required("service", "body", m.Service); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain a w s inventory filter setting based on context it is used
func (m *DomainAWSInventoryFilterSetting) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainAWSInventoryFilterSetting) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainAWSInventoryFilterSetting) UnmarshalBinary(b []byte) error {
	var res DomainAWSInventoryFilterSetting
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
