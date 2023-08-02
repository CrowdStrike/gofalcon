// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FalconxFileResource falconx file resource
//
// swagger:model falconx.FileResource
type FalconxFileResource struct {

	// language
	Language string `json:"language,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// rva
	Rva string `json:"rva,omitempty"`

	// size
	Size string `json:"size,omitempty"`

	// type
	Type string `json:"type,omitempty"`
}

// Validate validates this falconx file resource
func (m *FalconxFileResource) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this falconx file resource based on context it is used
func (m *FalconxFileResource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FalconxFileResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FalconxFileResource) UnmarshalBinary(b []byte) error {
	var res FalconxFileResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
