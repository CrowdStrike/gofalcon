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

// K8sassetsNodeEnrichmentData k8sassets node enrichment data
//
// swagger:model k8sassets.NodeEnrichmentData
type K8sassetsNodeEnrichmentData struct {

	// container count
	// Required: true
	ContainerCount *int64 `json:"container_count"`

	// pod count
	// Required: true
	PodCount *int64 `json:"pod_count"`
}

// Validate validates this k8sassets node enrichment data
func (m *K8sassetsNodeEnrichmentData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContainerCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePodCount(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *K8sassetsNodeEnrichmentData) validateContainerCount(formats strfmt.Registry) error {

	if err := validate.Required("container_count", "body", m.ContainerCount); err != nil {
		return err
	}

	return nil
}

func (m *K8sassetsNodeEnrichmentData) validatePodCount(formats strfmt.Registry) error {

	if err := validate.Required("pod_count", "body", m.PodCount); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this k8sassets node enrichment data based on context it is used
func (m *K8sassetsNodeEnrichmentData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *K8sassetsNodeEnrichmentData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *K8sassetsNodeEnrichmentData) UnmarshalBinary(b []byte) error {
	var res K8sassetsNodeEnrichmentData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
