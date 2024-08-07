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

// TypesActionRunEvent types action run event
//
// swagger:model types.ActionRunEvent
type TypesActionRunEvent struct {

	// flat data
	// Required: true
	FlatData map[string]string `json:"FlatData"`

	// additional data
	AdditionalData string `json:"additional_data,omitempty"`

	// data
	Data *TypesActionRunEventData `json:"data,omitempty"`

	// flat fields
	FlatFields []string `json:"flat_fields"`

	// id
	ID int64 `json:"id,omitempty"`

	// message
	Message string `json:"message,omitempty"`

	// object
	Object string `json:"object,omitempty"`

	// object type
	ObjectType string `json:"object_type,omitempty"`

	// send time
	SendTime *TypesTimestamp `json:"send_time,omitempty"`

	// status
	Status int32 `json:"status,omitempty"`
}

// Validate validates this types action run event
func (m *TypesActionRunEvent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFlatData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSendTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesActionRunEvent) validateFlatData(formats strfmt.Registry) error {

	if err := validate.Required("FlatData", "body", m.FlatData); err != nil {
		return err
	}

	return nil
}

func (m *TypesActionRunEvent) validateData(formats strfmt.Registry) error {
	if swag.IsZero(m.Data) { // not required
		return nil
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

func (m *TypesActionRunEvent) validateSendTime(formats strfmt.Registry) error {
	if swag.IsZero(m.SendTime) { // not required
		return nil
	}

	if m.SendTime != nil {
		if err := m.SendTime.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("send_time")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("send_time")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this types action run event based on the context it is used
func (m *TypesActionRunEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSendTime(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesActionRunEvent) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if m.Data != nil {

		if swag.IsZero(m.Data) { // not required
			return nil
		}

		if err := m.Data.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

func (m *TypesActionRunEvent) contextValidateSendTime(ctx context.Context, formats strfmt.Registry) error {

	if m.SendTime != nil {

		if swag.IsZero(m.SendTime) { // not required
			return nil
		}

		if err := m.SendTime.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("send_time")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("send_time")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TypesActionRunEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesActionRunEvent) UnmarshalBinary(b []byte) error {
	var res TypesActionRunEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
