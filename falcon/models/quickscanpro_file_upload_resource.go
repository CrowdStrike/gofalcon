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

// QuickscanproFileUploadResource quickscanpro file upload resource
//
// swagger:model quickscanpro.FileUploadResource
type QuickscanproFileUploadResource struct {

	// scan id
	ScanID string `json:"scan_id,omitempty"`

	// sha256
	// Required: true
	Sha256 *string `json:"sha256"`
}

// Validate validates this quickscanpro file upload resource
func (m *QuickscanproFileUploadResource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSha256(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *QuickscanproFileUploadResource) validateSha256(formats strfmt.Registry) error {

	if err := validate.Required("sha256", "body", m.Sha256); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this quickscanpro file upload resource based on context it is used
func (m *QuickscanproFileUploadResource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *QuickscanproFileUploadResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *QuickscanproFileUploadResource) UnmarshalBinary(b []byte) error {
	var res QuickscanproFileUploadResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
