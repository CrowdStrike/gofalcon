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

// ModelsDeployment models deployment
//
// swagger:model models.Deployment
type ModelsDeployment struct {

	// account id
	// Required: true
	AccountID *string `json:"account_id"`

	// asset identifier
	// Required: true
	AssetIdentifier *string `json:"asset_identifier"`

	// cloud provider
	// Required: true
	CloudProvider *string `json:"cloud_provider"`

	// id
	// Required: true
	ID *string `json:"id"`

	// instance type
	// Required: true
	InstanceType *string `json:"instance_type"`

	// last updated timestamp
	// Required: true
	LastUpdatedTimestamp *string `json:"last_updated_timestamp"`

	// region
	// Required: true
	Region *string `json:"region"`

	// status
	// Required: true
	Status *string `json:"status"`

	// status detail
	// Required: true
	StatusDetail *string `json:"status_detail"`
}

// Validate validates this models deployment
func (m *ModelsDeployment) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssetIdentifier(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInstanceType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastUpdatedTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRegion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatusDetail(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsDeployment) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("account_id", "body", m.AccountID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateAssetIdentifier(formats strfmt.Registry) error {

	if err := validate.Required("asset_identifier", "body", m.AssetIdentifier); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateCloudProvider(formats strfmt.Registry) error {

	if err := validate.Required("cloud_provider", "body", m.CloudProvider); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateInstanceType(formats strfmt.Registry) error {

	if err := validate.Required("instance_type", "body", m.InstanceType); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateLastUpdatedTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("last_updated_timestamp", "body", m.LastUpdatedTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateRegion(formats strfmt.Registry) error {

	if err := validate.Required("region", "body", m.Region); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *ModelsDeployment) validateStatusDetail(formats strfmt.Registry) error {

	if err := validate.Required("status_detail", "body", m.StatusDetail); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models deployment based on context it is used
func (m *ModelsDeployment) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsDeployment) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsDeployment) UnmarshalBinary(b []byte) error {
	var res ModelsDeployment
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
