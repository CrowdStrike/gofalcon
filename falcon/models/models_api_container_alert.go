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

// ModelsAPIContainerAlert models API container alert
//
// swagger:model models.APIContainerAlert
type ModelsAPIContainerAlert struct {

	// containers impacted count
	// Required: true
	ContainersImpactedCount *string `json:"containers_impacted_count"`

	// containers impacted ids
	// Required: true
	ContainersImpactedIds []string `json:"containers_impacted_ids"`

	// detection description
	// Required: true
	DetectionDescription *string `json:"detection_description"`

	// detection event simple name
	// Required: true
	DetectionEventSimpleName *string `json:"detection_event_simple_name"`

	// detection name
	// Required: true
	DetectionName *string `json:"detection_name"`

	// first seen timestamp
	// Required: true
	FirstSeenTimestamp *string `json:"first_seen_timestamp"`

	// last seen timestamp
	// Required: true
	LastSeenTimestamp *string `json:"last_seen_timestamp"`

	// severity
	// Required: true
	Severity *string `json:"severity"`
}

// Validate validates this models API container alert
func (m *ModelsAPIContainerAlert) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContainersImpactedCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContainersImpactedIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetectionDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetectionEventSimpleName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetectionName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFirstSeenTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastSeenTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsAPIContainerAlert) validateContainersImpactedCount(formats strfmt.Registry) error {

	if err := validate.Required("containers_impacted_count", "body", m.ContainersImpactedCount); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateContainersImpactedIds(formats strfmt.Registry) error {

	if err := validate.Required("containers_impacted_ids", "body", m.ContainersImpactedIds); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateDetectionDescription(formats strfmt.Registry) error {

	if err := validate.Required("detection_description", "body", m.DetectionDescription); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateDetectionEventSimpleName(formats strfmt.Registry) error {

	if err := validate.Required("detection_event_simple_name", "body", m.DetectionEventSimpleName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateDetectionName(formats strfmt.Registry) error {

	if err := validate.Required("detection_name", "body", m.DetectionName); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateFirstSeenTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("first_seen_timestamp", "body", m.FirstSeenTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateLastSeenTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("last_seen_timestamp", "body", m.LastSeenTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIContainerAlert) validateSeverity(formats strfmt.Registry) error {

	if err := validate.Required("severity", "body", m.Severity); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models API container alert based on context it is used
func (m *ModelsAPIContainerAlert) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsAPIContainerAlert) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsAPIContainerAlert) UnmarshalBinary(b []byte) error {
	var res ModelsAPIContainerAlert
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
