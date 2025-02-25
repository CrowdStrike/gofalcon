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

// ModelsResultProperties models result properties
//
// swagger:model models.ResultProperties
type ModelsResultProperties struct {

	// asset ID
	// Required: true
	AssetID *string `json:"assetID"`

	// asset name
	// Required: true
	AssetName *string `json:"assetName"`

	// asset type
	// Required: true
	AssetType *string `json:"assetType"`

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// cloud account ID
	// Required: true
	CloudAccountID *string `json:"cloudAccountID"`

	// cloud account name
	// Required: true
	CloudAccountName *string `json:"cloudAccountName"`

	// cloud provider
	// Required: true
	CloudProvider *string `json:"cloudProvider"`

	// function type
	// Required: true
	FunctionType *string `json:"functionType"`

	// is supported
	// Required: true
	IsSupported *bool `json:"isSupported"`

	// last analyzed at
	// Required: true
	LastAnalyzedAt *int64 `json:"last_analyzed_at"`

	// region
	// Required: true
	Region *string `json:"region"`
}

// Validate validates this models result properties
func (m *ModelsResultProperties) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAssetID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssetName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssetType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudAccountName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFunctionType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastAnalyzedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRegion(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsResultProperties) validateAssetID(formats strfmt.Registry) error {

	if err := validate.Required("assetID", "body", m.AssetID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateAssetName(formats strfmt.Registry) error {

	if err := validate.Required("assetName", "body", m.AssetName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateAssetType(formats strfmt.Registry) error {

	if err := validate.Required("assetType", "body", m.AssetType); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateCloudAccountID(formats strfmt.Registry) error {

	if err := validate.Required("cloudAccountID", "body", m.CloudAccountID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateCloudAccountName(formats strfmt.Registry) error {

	if err := validate.Required("cloudAccountName", "body", m.CloudAccountName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateCloudProvider(formats strfmt.Registry) error {

	if err := validate.Required("cloudProvider", "body", m.CloudProvider); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateFunctionType(formats strfmt.Registry) error {

	if err := validate.Required("functionType", "body", m.FunctionType); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateIsSupported(formats strfmt.Registry) error {

	if err := validate.Required("isSupported", "body", m.IsSupported); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateLastAnalyzedAt(formats strfmt.Registry) error {

	if err := validate.Required("last_analyzed_at", "body", m.LastAnalyzedAt); err != nil {
		return err
	}

	return nil
}

func (m *ModelsResultProperties) validateRegion(formats strfmt.Registry) error {

	if err := validate.Required("region", "body", m.Region); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models result properties based on context it is used
func (m *ModelsResultProperties) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsResultProperties) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsResultProperties) UnmarshalBinary(b []byte) error {
	var res ModelsResultProperties
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
