// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AccountIntegration78516f4af64a473daf4f3cf9a9c08930 account integration 78516f4af64a473daf4f3cf9a9c08930
//
// swagger:model AccountIntegration_78516f4af64a473daf4f3cf9a9c08930
type AccountIntegration78516f4af64a473daf4f3cf9a9c08930 struct {

	// Account id
	// Required: true
	AccountID *string `json:"account_id"`

	// Alias
	// Required: true
	// Min Length: 1
	Alias *string `json:"alias"`

	// Created time
	// Required: true
	// Format: date-time
	CreatedTime *strfmt.DateTime `json:"created_time"`

	// Enabled
	// Required: true
	Enabled *bool `json:"enabled"`

	// Id
	// Required: true
	ID *string `json:"id"`

	// Integration status
	// Required: true
	// Min Length: 1
	IntegrationStatus *string `json:"integration_status"`

	// issues
	// Required: true
	Issues []*Issue4540652743ff4130aee1870619a9cc0a `json:"issues"`

	// Last run
	// Required: true
	// Format: date-time
	LastRun *strfmt.DateTime `json:"last_run"`

	// Saas id
	// Required: true
	// Min Length: 1
	SaasID *string `json:"saas_id"`

	// Saas name
	// Required: true
	// Min Length: 1
	SaasName *string `json:"saas_name"`
}

// Validate validates this account integration 78516f4af64a473daf4f3cf9a9c08930
func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAlias(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntegrationStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssues(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastRun(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSaasID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSaasName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("account_id", "body", m.AccountID); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateAlias(formats strfmt.Registry) error {

	if err := validate.Required("alias", "body", m.Alias); err != nil {
		return err
	}

	if err := validate.MinLength("alias", "body", *m.Alias, 1); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateCreatedTime(formats strfmt.Registry) error {

	if err := validate.Required("created_time", "body", m.CreatedTime); err != nil {
		return err
	}

	if err := validate.FormatOf("created_time", "body", "date-time", m.CreatedTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateEnabled(formats strfmt.Registry) error {

	if err := validate.Required("enabled", "body", m.Enabled); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateIntegrationStatus(formats strfmt.Registry) error {

	if err := validate.Required("integration_status", "body", m.IntegrationStatus); err != nil {
		return err
	}

	if err := validate.MinLength("integration_status", "body", *m.IntegrationStatus, 1); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateIssues(formats strfmt.Registry) error {

	if err := validate.Required("issues", "body", m.Issues); err != nil {
		return err
	}

	for i := 0; i < len(m.Issues); i++ {
		if swag.IsZero(m.Issues[i]) { // not required
			continue
		}

		if m.Issues[i] != nil {
			if err := m.Issues[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("issues" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("issues" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateLastRun(formats strfmt.Registry) error {

	if err := validate.Required("last_run", "body", m.LastRun); err != nil {
		return err
	}

	if err := validate.FormatOf("last_run", "body", "date-time", m.LastRun.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateSaasID(formats strfmt.Registry) error {

	if err := validate.Required("saas_id", "body", m.SaasID); err != nil {
		return err
	}

	if err := validate.MinLength("saas_id", "body", *m.SaasID, 1); err != nil {
		return err
	}

	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) validateSaasName(formats strfmt.Registry) error {

	if err := validate.Required("saas_name", "body", m.SaasName); err != nil {
		return err
	}

	if err := validate.MinLength("saas_name", "body", *m.SaasName, 1); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this account integration 78516f4af64a473daf4f3cf9a9c08930 based on the context it is used
func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateIssues(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) contextValidateIssues(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Issues); i++ {

		if m.Issues[i] != nil {

			if swag.IsZero(m.Issues[i]) { // not required
				return nil
			}

			if err := m.Issues[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("issues" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("issues" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AccountIntegration78516f4af64a473daf4f3cf9a9c08930) UnmarshalBinary(b []byte) error {
	var res AccountIntegration78516f4af64a473daf4f3cf9a9c08930
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
