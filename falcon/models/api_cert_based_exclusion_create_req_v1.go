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

// APICertBasedExclusionCreateReqV1 api cert based exclusion create req v1
//
// swagger:model api.CertBasedExclusionCreateReqV1
type APICertBasedExclusionCreateReqV1 struct {

	// applied globally
	AppliedGlobally bool `json:"applied_globally,omitempty"`

	// certificate
	Certificate *APICertificateReqV1 `json:"certificate,omitempty"`

	// children cids
	ChildrenCids []string `json:"children_cids"`

	// comment
	Comment string `json:"comment,omitempty"`

	// created by
	CreatedBy string `json:"created_by,omitempty"`

	// created on
	// Format: date-time
	CreatedOn strfmt.DateTime `json:"created_on,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// host groups
	HostGroups []string `json:"host_groups"`

	// modified by
	ModifiedBy string `json:"modified_by,omitempty"`

	// modified on
	// Format: date-time
	ModifiedOn strfmt.DateTime `json:"modified_on,omitempty"`

	// name
	// Required: true
	Name *string `json:"name"`

	// status
	Status string `json:"status,omitempty"`
}

// Validate validates this api cert based exclusion create req v1
func (m *APICertBasedExclusionCreateReqV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCertificate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateModifiedOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APICertBasedExclusionCreateReqV1) validateCertificate(formats strfmt.Registry) error {
	if swag.IsZero(m.Certificate) { // not required
		return nil
	}

	if m.Certificate != nil {
		if err := m.Certificate.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("certificate")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("certificate")
			}
			return err
		}
	}

	return nil
}

func (m *APICertBasedExclusionCreateReqV1) validateCreatedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("created_on", "body", "date-time", m.CreatedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APICertBasedExclusionCreateReqV1) validateModifiedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.ModifiedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("modified_on", "body", "date-time", m.ModifiedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APICertBasedExclusionCreateReqV1) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this api cert based exclusion create req v1 based on the context it is used
func (m *APICertBasedExclusionCreateReqV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCertificate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APICertBasedExclusionCreateReqV1) contextValidateCertificate(ctx context.Context, formats strfmt.Registry) error {

	if m.Certificate != nil {

		if swag.IsZero(m.Certificate) { // not required
			return nil
		}

		if err := m.Certificate.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("certificate")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("certificate")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *APICertBasedExclusionCreateReqV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APICertBasedExclusionCreateReqV1) UnmarshalBinary(b []byte) error {
	var res APICertBasedExclusionCreateReqV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
