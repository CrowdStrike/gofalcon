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

// DomainMetaInfo domain meta info
//
// swagger:model domain.MetaInfo
type DomainMetaInfo struct {

	// pagination
	Pagination *MsaPaging `json:"pagination,omitempty"`

	// powered by
	PoweredBy string `json:"powered_by,omitempty"`

	// query time
	// Required: true
	QueryTime *float64 `json:"query_time"`

	// quota
	Quota *DomainQuota `json:"quota,omitempty"`

	// trace id
	// Required: true
	TraceID *string `json:"trace_id"`

	// writes
	Writes *MsaspecWrites `json:"writes,omitempty"`
}

// Validate validates this domain meta info
func (m *DomainMetaInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePagination(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQueryTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQuota(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTraceID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWrites(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainMetaInfo) validatePagination(formats strfmt.Registry) error {
	if swag.IsZero(m.Pagination) { // not required
		return nil
	}

	if m.Pagination != nil {
		if err := m.Pagination.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

func (m *DomainMetaInfo) validateQueryTime(formats strfmt.Registry) error {

	if err := validate.Required("query_time", "body", m.QueryTime); err != nil {
		return err
	}

	return nil
}

func (m *DomainMetaInfo) validateQuota(formats strfmt.Registry) error {
	if swag.IsZero(m.Quota) { // not required
		return nil
	}

	if m.Quota != nil {
		if err := m.Quota.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("quota")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("quota")
			}
			return err
		}
	}

	return nil
}

func (m *DomainMetaInfo) validateTraceID(formats strfmt.Registry) error {

	if err := validate.Required("trace_id", "body", m.TraceID); err != nil {
		return err
	}

	return nil
}

func (m *DomainMetaInfo) validateWrites(formats strfmt.Registry) error {
	if swag.IsZero(m.Writes) { // not required
		return nil
	}

	if m.Writes != nil {
		if err := m.Writes.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("writes")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("writes")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domain meta info based on the context it is used
func (m *DomainMetaInfo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePagination(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateQuota(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWrites(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainMetaInfo) contextValidatePagination(ctx context.Context, formats strfmt.Registry) error {

	if m.Pagination != nil {

		if swag.IsZero(m.Pagination) { // not required
			return nil
		}

		if err := m.Pagination.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

func (m *DomainMetaInfo) contextValidateQuota(ctx context.Context, formats strfmt.Registry) error {

	if m.Quota != nil {

		if swag.IsZero(m.Quota) { // not required
			return nil
		}

		if err := m.Quota.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("quota")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("quota")
			}
			return err
		}
	}

	return nil
}

func (m *DomainMetaInfo) contextValidateWrites(ctx context.Context, formats strfmt.Registry) error {

	if m.Writes != nil {

		if swag.IsZero(m.Writes) { // not required
			return nil
		}

		if err := m.Writes.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("writes")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("writes")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainMetaInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainMetaInfo) UnmarshalBinary(b []byte) error {
	var res DomainMetaInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
