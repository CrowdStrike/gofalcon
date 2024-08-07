// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesAWSMetadata types a w s metadata
//
// swagger:model types.AWSMetadata
type TypesAWSMetadata struct {

	// account arn
	AccountArn string `json:"accountArn,omitempty"`

	// region
	Region string `json:"region,omitempty"`
}

// Validate validates this types a w s metadata
func (m *TypesAWSMetadata) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types a w s metadata based on context it is used
func (m *TypesAWSMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesAWSMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesAWSMetadata) UnmarshalBinary(b []byte) error {
	var res TypesAWSMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
