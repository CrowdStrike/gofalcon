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

// ApidomainRepositoryV1 apidomain repository v1
//
// swagger:model apidomain.RepositoryV1
type ApidomainRepositoryV1 struct {

	// description
	// Required: true
	Description *string `json:"description"`

	// display name
	// Required: true
	DisplayName *string `json:"display_name"`

	// id
	// Required: true
	ID *string `json:"id"`

	// name
	// Required: true
	Name *string `json:"name"`

	// size
	// Required: true
	Size *int64 `json:"size"`
}

// Validate validates this apidomain repository v1
func (m *ApidomainRepositoryV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDisplayName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSize(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ApidomainRepositoryV1) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainRepositoryV1) validateDisplayName(formats strfmt.Registry) error {

	if err := validate.Required("display_name", "body", m.DisplayName); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainRepositoryV1) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainRepositoryV1) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainRepositoryV1) validateSize(formats strfmt.Registry) error {

	if err := validate.Required("size", "body", m.Size); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this apidomain repository v1 based on context it is used
func (m *ApidomainRepositoryV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ApidomainRepositoryV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ApidomainRepositoryV1) UnmarshalBinary(b []byte) error {
	var res ApidomainRepositoryV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
