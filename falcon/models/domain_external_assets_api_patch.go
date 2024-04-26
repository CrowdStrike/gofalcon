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

// DomainExternalAssetsAPIPatch Represents information about a managed, an unmanaged or an unsupported asset.
//
// swagger:model domain.ExternalAssetsAPIPatch
type DomainExternalAssetsAPIPatch struct {

	// The asset's customer ID.
	Cid string `json:"cid,omitempty"`

	// The criticality level manually assigned to this asset.
	Criticality string `json:"criticality,omitempty"`

	// The criticality description manually assigned to this asset.
	CriticalityDescription string `json:"criticality_description,omitempty"`

	// The unique ID of the asset.
	// Required: true
	ID *string `json:"id"`

	// The patch object definition to be applied to the asset
	Triage *DomainExternalAssetsAPITriagePatch `json:"triage,omitempty"`
}

// Validate validates this domain external assets API patch
func (m *DomainExternalAssetsAPIPatch) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTriage(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExternalAssetsAPIPatch) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAssetsAPIPatch) validateTriage(formats strfmt.Registry) error {
	if swag.IsZero(m.Triage) { // not required
		return nil
	}

	if m.Triage != nil {
		if err := m.Triage.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("triage")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("triage")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domain external assets API patch based on the context it is used
func (m *DomainExternalAssetsAPIPatch) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateTriage(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExternalAssetsAPIPatch) contextValidateTriage(ctx context.Context, formats strfmt.Registry) error {

	if m.Triage != nil {

		if swag.IsZero(m.Triage) { // not required
			return nil
		}

		if err := m.Triage.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("triage")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("triage")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainExternalAssetsAPIPatch) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainExternalAssetsAPIPatch) UnmarshalBinary(b []byte) error {
	var res DomainExternalAssetsAPIPatch
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
