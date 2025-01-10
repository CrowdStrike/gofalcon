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

// ResourcesDetections resources detections
//
// swagger:model resources.Detections
type ResourcesDetections struct {

	// compliant
	Compliant *ResourcesCompliance `json:"compliant,omitempty"`

	// highest severity
	HighestSeverity string `json:"highest_severity,omitempty"`

	// ioa counts
	// Required: true
	IoaCounts *int64 `json:"ioa_counts"`

	// iom counts
	// Required: true
	IomCounts *int64 `json:"iom_counts"`

	// non compliant
	NonCompliant *ResourcesCompliance `json:"non_compliant,omitempty"`

	// severities
	Severities []string `json:"severities"`
}

// Validate validates this resources detections
func (m *ResourcesDetections) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCompliant(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIoaCounts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIomCounts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNonCompliant(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResourcesDetections) validateCompliant(formats strfmt.Registry) error {
	if swag.IsZero(m.Compliant) { // not required
		return nil
	}

	if m.Compliant != nil {
		if err := m.Compliant.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("compliant")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("compliant")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesDetections) validateIoaCounts(formats strfmt.Registry) error {

	if err := validate.Required("ioa_counts", "body", m.IoaCounts); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesDetections) validateIomCounts(formats strfmt.Registry) error {

	if err := validate.Required("iom_counts", "body", m.IomCounts); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesDetections) validateNonCompliant(formats strfmt.Registry) error {
	if swag.IsZero(m.NonCompliant) { // not required
		return nil
	}

	if m.NonCompliant != nil {
		if err := m.NonCompliant.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("non_compliant")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("non_compliant")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this resources detections based on the context it is used
func (m *ResourcesDetections) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCompliant(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNonCompliant(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResourcesDetections) contextValidateCompliant(ctx context.Context, formats strfmt.Registry) error {

	if m.Compliant != nil {

		if swag.IsZero(m.Compliant) { // not required
			return nil
		}

		if err := m.Compliant.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("compliant")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("compliant")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesDetections) contextValidateNonCompliant(ctx context.Context, formats strfmt.Registry) error {

	if m.NonCompliant != nil {

		if swag.IsZero(m.NonCompliant) { // not required
			return nil
		}

		if err := m.NonCompliant.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("non_compliant")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("non_compliant")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ResourcesDetections) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResourcesDetections) UnmarshalBinary(b []byte) error {
	var res ResourcesDetections
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
