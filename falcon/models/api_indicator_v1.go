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

// APIIndicatorV1 api indicator v1
//
// swagger:model api.IndicatorV1
type APIIndicatorV1 struct {

	// action
	Action string `json:"action,omitempty"`

	// applied globally
	AppliedGlobally bool `json:"applied_globally,omitempty"`

	// created by
	CreatedBy string `json:"created_by,omitempty"`

	// created on
	// Format: date-time
	CreatedOn strfmt.DateTime `json:"created_on,omitempty"`

	// deleted
	Deleted bool `json:"deleted,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// expiration
	// Format: date-time
	Expiration strfmt.DateTime `json:"expiration,omitempty"`

	// expired
	Expired bool `json:"expired,omitempty"`

	// from parent
	FromParent bool `json:"from_parent,omitempty"`

	// host groups
	HostGroups []string `json:"host_groups"`

	// id
	ID string `json:"id,omitempty"`

	// metadata
	Metadata *APIMetadataV1 `json:"metadata,omitempty"`

	// mobile action
	MobileAction string `json:"mobile_action,omitempty"`

	// modified by
	ModifiedBy string `json:"modified_by,omitempty"`

	// modified on
	// Format: date-time
	ModifiedOn strfmt.DateTime `json:"modified_on,omitempty"`

	// parent cid name
	ParentCidName string `json:"parent_cid_name,omitempty"`

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

// Validate validates this api indicator v1
func (m *APIIndicatorV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateModifiedOn(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIIndicatorV1) validateCreatedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("created_on", "body", "date-time", m.CreatedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIIndicatorV1) validateExpiration(formats strfmt.Registry) error {
	if swag.IsZero(m.Expiration) { // not required
		return nil
	}

	if err := validate.FormatOf("expiration", "body", "date-time", m.Expiration.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIIndicatorV1) validateMetadata(formats strfmt.Registry) error {
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

func (m *APIIndicatorV1) validateModifiedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.ModifiedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("modified_on", "body", "date-time", m.ModifiedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this api indicator v1 based on the context it is used
func (m *APIIndicatorV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIIndicatorV1) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

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
func (m *APIIndicatorV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIIndicatorV1) UnmarshalBinary(b []byte) error {
	var res APIIndicatorV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
