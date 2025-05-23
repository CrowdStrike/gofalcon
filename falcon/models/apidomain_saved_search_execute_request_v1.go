// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ApidomainSavedSearchExecuteRequestV1 apidomain saved search execute request v1
//
// swagger:model apidomain.SavedSearchExecuteRequestV1
type ApidomainSavedSearchExecuteRequestV1 struct {

	// end
	End string `json:"end,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// mode
	Mode string `json:"mode,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// parameters
	// Required: true
	Parameters map[string]string `json:"Parameters"`

	// start
	Start string `json:"start,omitempty"`

	// version
	Version string `json:"version,omitempty"`

	// with in
	WithIn *ClientExtraIn `json:"with_in,omitempty"`

	// with limit
	WithLimit *ClientExtraLimit `json:"with_limit,omitempty"`

	// with renames
	WithRenames []*ClientExtraRename `json:"with_renames"`

	// with sort
	WithSort *ClientExtraSort `json:"with_sort,omitempty"`
}

// Validate validates this apidomain saved search execute request v1
func (m *ApidomainSavedSearchExecuteRequestV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateWithIn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWithLimit(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWithRenames(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWithSort(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) validateWithIn(formats strfmt.Registry) error {
	if swag.IsZero(m.WithIn) { // not required
		return nil
	}

	if m.WithIn != nil {
		if err := m.WithIn.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("with_in")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("with_in")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) validateWithLimit(formats strfmt.Registry) error {
	if swag.IsZero(m.WithLimit) { // not required
		return nil
	}

	if m.WithLimit != nil {
		if err := m.WithLimit.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("with_limit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("with_limit")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) validateWithRenames(formats strfmt.Registry) error {
	if swag.IsZero(m.WithRenames) { // not required
		return nil
	}

	for i := 0; i < len(m.WithRenames); i++ {
		if swag.IsZero(m.WithRenames[i]) { // not required
			continue
		}

		if m.WithRenames[i] != nil {
			if err := m.WithRenames[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("with_renames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("with_renames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) validateWithSort(formats strfmt.Registry) error {
	if swag.IsZero(m.WithSort) { // not required
		return nil
	}

	if m.WithSort != nil {
		if err := m.WithSort.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("with_sort")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("with_sort")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this apidomain saved search execute request v1 based on the context it is used
func (m *ApidomainSavedSearchExecuteRequestV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateWithIn(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWithLimit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWithRenames(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWithSort(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) contextValidateWithIn(ctx context.Context, formats strfmt.Registry) error {

	if m.WithIn != nil {

		if swag.IsZero(m.WithIn) { // not required
			return nil
		}

		if err := m.WithIn.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("with_in")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("with_in")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) contextValidateWithLimit(ctx context.Context, formats strfmt.Registry) error {

	if m.WithLimit != nil {

		if swag.IsZero(m.WithLimit) { // not required
			return nil
		}

		if err := m.WithLimit.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("with_limit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("with_limit")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) contextValidateWithRenames(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.WithRenames); i++ {

		if m.WithRenames[i] != nil {

			if swag.IsZero(m.WithRenames[i]) { // not required
				return nil
			}

			if err := m.WithRenames[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("with_renames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("with_renames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ApidomainSavedSearchExecuteRequestV1) contextValidateWithSort(ctx context.Context, formats strfmt.Registry) error {

	if m.WithSort != nil {

		if swag.IsZero(m.WithSort) { // not required
			return nil
		}

		if err := m.WithSort.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("with_sort")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("with_sort")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ApidomainSavedSearchExecuteRequestV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ApidomainSavedSearchExecuteRequestV1) UnmarshalBinary(b []byte) error {
	var res ApidomainSavedSearchExecuteRequestV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
