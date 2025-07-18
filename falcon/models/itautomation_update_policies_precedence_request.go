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

// ItautomationUpdatePoliciesPrecedenceRequest itautomation update policies precedence request
//
// swagger:model itautomation.UpdatePoliciesPrecedenceRequest
type ItautomationUpdatePoliciesPrecedenceRequest struct {

	// IDs of all the policy in precedence order for a give platform.
	// Required: true
	Ids []string `json:"ids"`
}

// Validate validates this itautomation update policies precedence request
func (m *ItautomationUpdatePoliciesPrecedenceRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateIds(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ItautomationUpdatePoliciesPrecedenceRequest) validateIds(formats strfmt.Registry) error {

	if err := validate.Required("ids", "body", m.Ids); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this itautomation update policies precedence request based on context it is used
func (m *ItautomationUpdatePoliciesPrecedenceRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ItautomationUpdatePoliciesPrecedenceRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ItautomationUpdatePoliciesPrecedenceRequest) UnmarshalBinary(b []byte) error {
	var res ItautomationUpdatePoliciesPrecedenceRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
