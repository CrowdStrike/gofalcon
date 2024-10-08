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

// ThreatgraphVertexDetails threatgraph vertex details
//
// swagger:model threatgraph.VertexDetails
type ThreatgraphVertexDetails struct {

	// customer id
	// Required: true
	CustomerID *string `json:"customer_id"`

	// device id
	DeviceID string `json:"device_id,omitempty"`

	// id
	// Required: true
	ID *string `json:"id"`

	// object id
	ObjectID string `json:"object_id,omitempty"`

	// properties
	// Required: true
	Properties interface{} `json:"properties"`

	// scope
	// Required: true
	Scope *string `json:"scope"`

	// timestamp
	// Required: true
	Timestamp *string `json:"timestamp"`

	// vertex type
	// Required: true
	VertexType *string `json:"vertex_type"`
}

// Validate validates this threatgraph vertex details
func (m *ThreatgraphVertexDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCustomerID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProperties(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScope(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVertexType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ThreatgraphVertexDetails) validateCustomerID(formats strfmt.Registry) error {

	if err := validate.Required("customer_id", "body", m.CustomerID); err != nil {
		return err
	}

	return nil
}

func (m *ThreatgraphVertexDetails) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *ThreatgraphVertexDetails) validateProperties(formats strfmt.Registry) error {

	if m.Properties == nil {
		return errors.Required("properties", "body", nil)
	}

	return nil
}

func (m *ThreatgraphVertexDetails) validateScope(formats strfmt.Registry) error {

	if err := validate.Required("scope", "body", m.Scope); err != nil {
		return err
	}

	return nil
}

func (m *ThreatgraphVertexDetails) validateTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("timestamp", "body", m.Timestamp); err != nil {
		return err
	}

	return nil
}

func (m *ThreatgraphVertexDetails) validateVertexType(formats strfmt.Registry) error {

	if err := validate.Required("vertex_type", "body", m.VertexType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this threatgraph vertex details based on context it is used
func (m *ThreatgraphVertexDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ThreatgraphVertexDetails) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ThreatgraphVertexDetails) UnmarshalBinary(b []byte) error {
	var res ThreatgraphVertexDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}