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

// EntitiesRollingAverage entities rolling average
//
// swagger:model entities.RollingAverage
type EntitiesRollingAverage struct {

	// chrome os
	// Required: true
	ChromeOs *float64 `json:"chrome_os"`

	// containers
	// Required: true
	Containers *float64 `json:"containers"`

	// date
	// Required: true
	// Format: date
	Date *strfmt.Date `json:"date"`

	// lumos
	// Required: true
	Lumos *float64 `json:"lumos"`

	// mobile
	// Required: true
	Mobile *float64 `json:"mobile"`

	// public cloud with containers
	// Required: true
	PublicCloudWithContainers *float64 `json:"public_cloud_with_containers"`

	// public cloud without containers
	// Required: true
	PublicCloudWithoutContainers *float64 `json:"public_cloud_without_containers"`

	// servers with containers
	// Required: true
	ServersWithContainers *float64 `json:"servers_with_containers"`

	// servers without containers
	// Required: true
	ServersWithoutContainers *float64 `json:"servers_without_containers"`

	// workstations
	// Required: true
	Workstations *float64 `json:"workstations"`
}

// Validate validates this entities rolling average
func (m *EntitiesRollingAverage) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateChromeOs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContainers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLumos(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMobile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicCloudWithContainers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicCloudWithoutContainers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServersWithContainers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServersWithoutContainers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWorkstations(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EntitiesRollingAverage) validateChromeOs(formats strfmt.Registry) error {

	if err := validate.Required("chrome_os", "body", m.ChromeOs); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateContainers(formats strfmt.Registry) error {

	if err := validate.Required("containers", "body", m.Containers); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateDate(formats strfmt.Registry) error {

	if err := validate.Required("date", "body", m.Date); err != nil {
		return err
	}

	if err := validate.FormatOf("date", "body", "date", m.Date.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateLumos(formats strfmt.Registry) error {

	if err := validate.Required("lumos", "body", m.Lumos); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateMobile(formats strfmt.Registry) error {

	if err := validate.Required("mobile", "body", m.Mobile); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validatePublicCloudWithContainers(formats strfmt.Registry) error {

	if err := validate.Required("public_cloud_with_containers", "body", m.PublicCloudWithContainers); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validatePublicCloudWithoutContainers(formats strfmt.Registry) error {

	if err := validate.Required("public_cloud_without_containers", "body", m.PublicCloudWithoutContainers); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateServersWithContainers(formats strfmt.Registry) error {

	if err := validate.Required("servers_with_containers", "body", m.ServersWithContainers); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateServersWithoutContainers(formats strfmt.Registry) error {

	if err := validate.Required("servers_without_containers", "body", m.ServersWithoutContainers); err != nil {
		return err
	}

	return nil
}

func (m *EntitiesRollingAverage) validateWorkstations(formats strfmt.Registry) error {

	if err := validate.Required("workstations", "body", m.Workstations); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this entities rolling average based on context it is used
func (m *EntitiesRollingAverage) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EntitiesRollingAverage) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EntitiesRollingAverage) UnmarshalBinary(b []byte) error {
	var res EntitiesRollingAverage
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
