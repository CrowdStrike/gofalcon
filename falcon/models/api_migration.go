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

// APIMigration api migration
//
// swagger:model api.Migration
type APIMigration struct {

	// canceled by
	CanceledBy string `json:"canceled_by,omitempty"`

	// completed time
	// Format: date-time
	CompletedTime strfmt.DateTime `json:"completed_time,omitempty"`

	// created by
	// Required: true
	CreatedBy *string `json:"created_by"`

	// created time
	// Required: true
	// Format: date-time
	CreatedTime *strfmt.DateTime `json:"created_time"`

	// migration id
	// Required: true
	MigrationID *string `json:"migration_id"`

	// migration status
	// Required: true
	MigrationStatus *string `json:"migration_status"`

	// name
	// Required: true
	Name *string `json:"name"`

	// started time
	// Format: date-time
	StartedTime strfmt.DateTime `json:"started_time,omitempty"`

	// target cid
	// Required: true
	TargetCid *string `json:"target_cid"`

	// total hosts
	// Required: true
	TotalHosts *int32 `json:"total_hosts"`

	// updated by
	// Required: true
	UpdatedBy *string `json:"updated_by"`

	// updated time
	// Required: true
	// Format: date-time
	UpdatedTime *strfmt.DateTime `json:"updated_time"`
}

// Validate validates this api migration
func (m *APIMigration) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCompletedTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMigrationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMigrationStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartedTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalHosts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIMigration) validateCompletedTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CompletedTime) { // not required
		return nil
	}

	if err := validate.FormatOf("completed_time", "body", "date-time", m.CompletedTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateCreatedBy(formats strfmt.Registry) error {

	if err := validate.Required("created_by", "body", m.CreatedBy); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateCreatedTime(formats strfmt.Registry) error {

	if err := validate.Required("created_time", "body", m.CreatedTime); err != nil {
		return err
	}

	if err := validate.FormatOf("created_time", "body", "date-time", m.CreatedTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateMigrationID(formats strfmt.Registry) error {

	if err := validate.Required("migration_id", "body", m.MigrationID); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateMigrationStatus(formats strfmt.Registry) error {

	if err := validate.Required("migration_status", "body", m.MigrationStatus); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateStartedTime(formats strfmt.Registry) error {
	if swag.IsZero(m.StartedTime) { // not required
		return nil
	}

	if err := validate.FormatOf("started_time", "body", "date-time", m.StartedTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateTargetCid(formats strfmt.Registry) error {

	if err := validate.Required("target_cid", "body", m.TargetCid); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateTotalHosts(formats strfmt.Registry) error {

	if err := validate.Required("total_hosts", "body", m.TotalHosts); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateUpdatedBy(formats strfmt.Registry) error {

	if err := validate.Required("updated_by", "body", m.UpdatedBy); err != nil {
		return err
	}

	return nil
}

func (m *APIMigration) validateUpdatedTime(formats strfmt.Registry) error {

	if err := validate.Required("updated_time", "body", m.UpdatedTime); err != nil {
		return err
	}

	if err := validate.FormatOf("updated_time", "body", "date-time", m.UpdatedTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this api migration based on context it is used
func (m *APIMigration) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIMigration) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIMigration) UnmarshalBinary(b []byte) error {
	var res APIMigration
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
