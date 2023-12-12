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

// K8sassetsPodEnrichmentEntry k8sassets pod enrichment entry
//
// swagger:model k8sassets.PodEnrichmentEntry
type K8sassetsPodEnrichmentEntry struct {

	// enrichment data
	// Required: true
	EnrichmentData *K8sassetsPodEnrichmentData `json:"enrichment_data"`

	// pod id
	// Required: true
	PodID *string `json:"pod_id"`
}

// Validate validates this k8sassets pod enrichment entry
func (m *K8sassetsPodEnrichmentEntry) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEnrichmentData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePodID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *K8sassetsPodEnrichmentEntry) validateEnrichmentData(formats strfmt.Registry) error {

	if err := validate.Required("enrichment_data", "body", m.EnrichmentData); err != nil {
		return err
	}

	if m.EnrichmentData != nil {
		if err := m.EnrichmentData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("enrichment_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("enrichment_data")
			}
			return err
		}
	}

	return nil
}

func (m *K8sassetsPodEnrichmentEntry) validatePodID(formats strfmt.Registry) error {

	if err := validate.Required("pod_id", "body", m.PodID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this k8sassets pod enrichment entry based on the context it is used
func (m *K8sassetsPodEnrichmentEntry) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEnrichmentData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *K8sassetsPodEnrichmentEntry) contextValidateEnrichmentData(ctx context.Context, formats strfmt.Registry) error {

	if m.EnrichmentData != nil {

		if err := m.EnrichmentData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("enrichment_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("enrichment_data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *K8sassetsPodEnrichmentEntry) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *K8sassetsPodEnrichmentEntry) UnmarshalBinary(b []byte) error {
	var res K8sassetsPodEnrichmentEntry
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
