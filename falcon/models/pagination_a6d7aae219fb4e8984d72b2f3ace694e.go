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

// PaginationA6d7aae219fb4e8984d72b2f3ace694e pagination a6d7aae219fb4e8984d72b2f3ace694e
//
// swagger:model Pagination_a6d7aae219fb4e8984d72b2f3ace694e
type PaginationA6d7aae219fb4e8984d72b2f3ace694e struct {

	// Limit
	Limit *int64 `json:"limit,omitempty"`

	// Next
	// Min Length: 1
	Next *string `json:"next,omitempty"`

	// Offset
	Offset *int64 `json:"offset,omitempty"`

	// Previous
	// Min Length: 1
	Previous *string `json:"previous,omitempty"`

	// Total
	Total *int64 `json:"total,omitempty"`
}

// Validate validates this pagination a6d7aae219fb4e8984d72b2f3ace694e
func (m *PaginationA6d7aae219fb4e8984d72b2f3ace694e) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrevious(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PaginationA6d7aae219fb4e8984d72b2f3ace694e) validateNext(formats strfmt.Registry) error {
	if swag.IsZero(m.Next) { // not required
		return nil
	}

	if err := validate.MinLength("next", "body", *m.Next, 1); err != nil {
		return err
	}

	return nil
}

func (m *PaginationA6d7aae219fb4e8984d72b2f3ace694e) validatePrevious(formats strfmt.Registry) error {
	if swag.IsZero(m.Previous) { // not required
		return nil
	}

	if err := validate.MinLength("previous", "body", *m.Previous, 1); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this pagination a6d7aae219fb4e8984d72b2f3ace694e based on context it is used
func (m *PaginationA6d7aae219fb4e8984d72b2f3ace694e) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PaginationA6d7aae219fb4e8984d72b2f3ace694e) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PaginationA6d7aae219fb4e8984d72b2f3ace694e) UnmarshalBinary(b []byte) error {
	var res PaginationA6d7aae219fb4e8984d72b2f3ace694e
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
