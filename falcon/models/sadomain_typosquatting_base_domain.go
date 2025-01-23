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

// SadomainTyposquattingBaseDomain sadomain typosquatting base domain
//
// swagger:model sadomain.TyposquattingBaseDomain
type SadomainTyposquattingBaseDomain struct {

	// The date when the domain was registered
	// Format: date-time
	CreatedDate strfmt.DateTime `json:"created_date,omitempty"`

	// The ID of the domain
	// Required: true
	ID *string `json:"id"`

	// Whether the domain has a valid Whois record
	// Required: true
	IsRegistered *bool `json:"is_registered"`

	// The Punycode representation of the domain, i.e. starting with `xn--`
	// Required: true
	PunycodeFormat *string `json:"punycode_format"`

	// submit for blocking info
	SubmitForBlockingInfo *SadomainSubmissionInformation `json:"submit_for_blocking_info,omitempty"`

	// submit for takedown info
	SubmitForTakedownInfo *SadomainSubmissionInformation `json:"submit_for_takedown_info,omitempty"`

	// The Unicode representation of the domain
	// Required: true
	UnicodeFormat *string `json:"unicode_format"`

	// The Whois record for the domain
	Whois *SadomainWhoisRecord `json:"whois,omitempty"`
}

// Validate validates this sadomain typosquatting base domain
func (m *SadomainTyposquattingBaseDomain) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsRegistered(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePunycodeFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubmitForBlockingInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubmitForTakedownInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUnicodeFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWhois(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateCreatedDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDate) { // not required
		return nil
	}

	if err := validate.FormatOf("created_date", "body", "date-time", m.CreatedDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateIsRegistered(formats strfmt.Registry) error {

	if err := validate.Required("is_registered", "body", m.IsRegistered); err != nil {
		return err
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validatePunycodeFormat(formats strfmt.Registry) error {

	if err := validate.Required("punycode_format", "body", m.PunycodeFormat); err != nil {
		return err
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateSubmitForBlockingInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.SubmitForBlockingInfo) { // not required
		return nil
	}

	if m.SubmitForBlockingInfo != nil {
		if err := m.SubmitForBlockingInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("submit_for_blocking_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("submit_for_blocking_info")
			}
			return err
		}
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateSubmitForTakedownInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.SubmitForTakedownInfo) { // not required
		return nil
	}

	if m.SubmitForTakedownInfo != nil {
		if err := m.SubmitForTakedownInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("submit_for_takedown_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("submit_for_takedown_info")
			}
			return err
		}
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateUnicodeFormat(formats strfmt.Registry) error {

	if err := validate.Required("unicode_format", "body", m.UnicodeFormat); err != nil {
		return err
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) validateWhois(formats strfmt.Registry) error {
	if swag.IsZero(m.Whois) { // not required
		return nil
	}

	if m.Whois != nil {
		if err := m.Whois.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("whois")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("whois")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this sadomain typosquatting base domain based on the context it is used
func (m *SadomainTyposquattingBaseDomain) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSubmitForBlockingInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubmitForTakedownInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWhois(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SadomainTyposquattingBaseDomain) contextValidateSubmitForBlockingInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.SubmitForBlockingInfo != nil {

		if swag.IsZero(m.SubmitForBlockingInfo) { // not required
			return nil
		}

		if err := m.SubmitForBlockingInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("submit_for_blocking_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("submit_for_blocking_info")
			}
			return err
		}
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) contextValidateSubmitForTakedownInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.SubmitForTakedownInfo != nil {

		if swag.IsZero(m.SubmitForTakedownInfo) { // not required
			return nil
		}

		if err := m.SubmitForTakedownInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("submit_for_takedown_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("submit_for_takedown_info")
			}
			return err
		}
	}

	return nil
}

func (m *SadomainTyposquattingBaseDomain) contextValidateWhois(ctx context.Context, formats strfmt.Registry) error {

	if m.Whois != nil {

		if swag.IsZero(m.Whois) { // not required
			return nil
		}

		if err := m.Whois.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("whois")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("whois")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SadomainTyposquattingBaseDomain) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SadomainTyposquattingBaseDomain) UnmarshalBinary(b []byte) error {
	var res SadomainTyposquattingBaseDomain
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
