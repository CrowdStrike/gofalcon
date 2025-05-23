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

// TypesActionRun types action run
//
// swagger:model types.ActionRun
type TypesActionRun struct {

	// create time
	CreateTime string `json:"createTime,omitempty"`

	// events
	Events []*TypesActionRunEvent `json:"events"`

	// id
	ID string `json:"id,omitempty"`

	// latest event
	LatestEvent *TypesActionRunEvent `json:"latestEvent,omitempty"`

	// metadata
	Metadata *TypesActionRunMetadata `json:"metadata,omitempty"`

	// progress
	Progress int32 `json:"progress,omitempty"`

	// scheduled
	Scheduled bool `json:"scheduled,omitempty"`

	// trace Uuid
	TraceUUID string `json:"traceUuid,omitempty"`
}

// Validate validates this types action run
func (m *TypesActionRun) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEvents(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLatestEvent(formats); err != nil {
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

func (m *TypesActionRun) validateEvents(formats strfmt.Registry) error {
	if swag.IsZero(m.Events) { // not required
		return nil
	}

	for i := 0; i < len(m.Events); i++ {
		if swag.IsZero(m.Events[i]) { // not required
			continue
		}

		if m.Events[i] != nil {
			if err := m.Events[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("events" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("events" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TypesActionRun) validateLatestEvent(formats strfmt.Registry) error {
	if swag.IsZero(m.LatestEvent) { // not required
		return nil
	}

	if m.LatestEvent != nil {
		if err := m.LatestEvent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("latestEvent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("latestEvent")
			}
			return err
		}
	}

	return nil
}

func (m *TypesActionRun) validateMetadata(formats strfmt.Registry) error {
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

// ContextValidate validate this types action run based on the context it is used
func (m *TypesActionRun) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEvents(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLatestEvent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesActionRun) contextValidateEvents(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Events); i++ {

		if m.Events[i] != nil {

			if swag.IsZero(m.Events[i]) { // not required
				return nil
			}

			if err := m.Events[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("events" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("events" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TypesActionRun) contextValidateLatestEvent(ctx context.Context, formats strfmt.Registry) error {

	if m.LatestEvent != nil {

		if swag.IsZero(m.LatestEvent) { // not required
			return nil
		}

		if err := m.LatestEvent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("latestEvent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("latestEvent")
			}
			return err
		}
	}

	return nil
}

func (m *TypesActionRun) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

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
func (m *TypesActionRun) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesActionRun) UnmarshalBinary(b []byte) error {
	var res TypesActionRun
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
