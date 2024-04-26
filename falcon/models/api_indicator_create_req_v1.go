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

// APIIndicatorCreateReqV1 api indicator create req v1
//
// swagger:model api.IndicatorCreateReqV1
type APIIndicatorCreateReqV1 struct {

	// action
	Action string `json:"action,omitempty"`

	// applied globally
	// Required: true
	AppliedGlobally *bool `json:"applied_globally"`

	// description
	Description string `json:"description,omitempty"`

	// expiration
	// Format: date-time
	Expiration *strfmt.DateTime `json:"expiration,omitempty"`

	// host groups
	HostGroups []string `json:"host_groups"`

	// metadata
	Metadata *APIMetadataReqV1 `json:"metadata,omitempty"`

	// mobile action
	MobileAction string `json:"mobile_action,omitempty"`

	// platforms
	Platforms []string `json:"platforms"`

	// severity
	Severity string `json:"severity,omitempty"`

	// source
	Source string `json:"source,omitempty"`

	// tags
	Tags []string `json:"tags"`

	// type
	Type string `json:"type,omitempty"`

	// value
	Value string `json:"value,omitempty"`
}

// Validate validates this api indicator create req v1
func (m *APIIndicatorCreateReqV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAppliedGlobally(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIIndicatorCreateReqV1) validateAppliedGlobally(formats strfmt.Registry) error {

	if err := validate.Required("applied_globally", "body", m.AppliedGlobally); err != nil {
		return err
	}

	return nil
}

func (m *APIIndicatorCreateReqV1) validateExpiration(formats strfmt.Registry) error {
	if swag.IsZero(m.Expiration) { // not required
		return nil
	}

	if err := validate.FormatOf("expiration", "body", "date-time", m.Expiration.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIIndicatorCreateReqV1) validateMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if m.Metadata != nil {
		if err := m.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this api indicator create req v1 based on the context it is used
func (m *APIIndicatorCreateReqV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIIndicatorCreateReqV1) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if m.Metadata != nil {

		if swag.IsZero(m.Metadata) { // not required
			return nil
		}

		if err := m.Metadata.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *APIIndicatorCreateReqV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIIndicatorCreateReqV1) UnmarshalBinary(b []byte) error {
	var res APIIndicatorCreateReqV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
