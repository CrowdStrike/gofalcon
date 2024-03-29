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

// ModelsImageInformation models image information
//
// swagger:model models.ImageInformation
type ModelsImageInformation struct {

	// image digest
	// Required: true
	ImageDigest *string `json:"image_digest"`

	// image id
	// Required: true
	ImageID *string `json:"image_id"`

	// image name
	// Required: true
	ImageName *string `json:"image_name"`
}

// Validate validates this models image information
func (m *ModelsImageInformation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateImageDigest(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateImageID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateImageName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsImageInformation) validateImageDigest(formats strfmt.Registry) error {

	if err := validate.Required("image_digest", "body", m.ImageDigest); err != nil {
		return err
	}

	return nil
}

func (m *ModelsImageInformation) validateImageID(formats strfmt.Registry) error {

	if err := validate.Required("image_id", "body", m.ImageID); err != nil {
		return err
	}

	return nil
}

func (m *ModelsImageInformation) validateImageName(formats strfmt.Registry) error {

	if err := validate.Required("image_name", "body", m.ImageName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models image information based on context it is used
func (m *ModelsImageInformation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsImageInformation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsImageInformation) UnmarshalBinary(b []byte) error {
	var res ModelsImageInformation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
