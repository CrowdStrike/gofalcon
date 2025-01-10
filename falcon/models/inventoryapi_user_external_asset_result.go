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

// InventoryapiUserExternalAssetResult inventoryapi user external asset result
//
// swagger:model inventoryapi.UserExternalAssetResult
type InventoryapiUserExternalAssetResult struct {

	// Asset type
	AssetType string `json:"asset_type,omitempty"`

	// The subsidiary that the asset belongs to in DFG
	CurrentSubsidiary *InventoryapidomainSubsidiary `json:"current_subsidiary,omitempty"`

	// The error for validation result
	Error *InventoryapiSurfaceError `json:"error,omitempty"`

	// The ID of the asset
	// Required: true
	ID *string `json:"id"`

	// The index of the asset
	// Required: true
	Index *int32 `json:"index"`

	// Raw value of the asset to be created
	// Required: true
	RawValue *string `json:"raw_value"`

	// The new subsidiary that the asset to be added to
	// Required: true
	Subsidiary *InventoryapidomainSubsidiary `json:"subsidiary"`

	// Asset
	Value string `json:"value,omitempty"`
}

// Validate validates this inventoryapi user external asset result
func (m *InventoryapiUserExternalAssetResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCurrentSubsidiary(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateError(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIndex(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRawValue(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubsidiary(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InventoryapiUserExternalAssetResult) validateCurrentSubsidiary(formats strfmt.Registry) error {
	if swag.IsZero(m.CurrentSubsidiary) { // not required
		return nil
	}

	if m.CurrentSubsidiary != nil {
		if err := m.CurrentSubsidiary.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("current_subsidiary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("current_subsidiary")
			}
			return err
		}
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) validateError(formats strfmt.Registry) error {
	if swag.IsZero(m.Error) { // not required
		return nil
	}

	if m.Error != nil {
		if err := m.Error.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("error")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("error")
			}
			return err
		}
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) validateIndex(formats strfmt.Registry) error {

	if err := validate.Required("index", "body", m.Index); err != nil {
		return err
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) validateRawValue(formats strfmt.Registry) error {

	if err := validate.Required("raw_value", "body", m.RawValue); err != nil {
		return err
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) validateSubsidiary(formats strfmt.Registry) error {

	if err := validate.Required("subsidiary", "body", m.Subsidiary); err != nil {
		return err
	}

	if m.Subsidiary != nil {
		if err := m.Subsidiary.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("subsidiary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("subsidiary")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this inventoryapi user external asset result based on the context it is used
func (m *InventoryapiUserExternalAssetResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCurrentSubsidiary(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateError(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSubsidiary(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InventoryapiUserExternalAssetResult) contextValidateCurrentSubsidiary(ctx context.Context, formats strfmt.Registry) error {

	if m.CurrentSubsidiary != nil {

		if swag.IsZero(m.CurrentSubsidiary) { // not required
			return nil
		}

		if err := m.CurrentSubsidiary.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("current_subsidiary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("current_subsidiary")
			}
			return err
		}
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) contextValidateError(ctx context.Context, formats strfmt.Registry) error {

	if m.Error != nil {

		if swag.IsZero(m.Error) { // not required
			return nil
		}

		if err := m.Error.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("error")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("error")
			}
			return err
		}
	}

	return nil
}

func (m *InventoryapiUserExternalAssetResult) contextValidateSubsidiary(ctx context.Context, formats strfmt.Registry) error {

	if m.Subsidiary != nil {

		if err := m.Subsidiary.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("subsidiary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("subsidiary")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *InventoryapiUserExternalAssetResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InventoryapiUserExternalAssetResult) UnmarshalBinary(b []byte) error {
	var res InventoryapiUserExternalAssetResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
