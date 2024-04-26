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

// DomainDenormalizedThreatUsedMitre domain denormalized threat used mitre
//
// swagger:model domain.DenormalizedThreatUsedMitre
type DomainDenormalizedThreatUsedMitre struct {

	// attack id
	AttackID string `json:"attack_id,omitempty"`

	// observables
	Observables []string `json:"observables"`

	// reports
	Reports []*DomainDenormalizedReportReference `json:"reports"`

	// tactic id
	TacticID string `json:"tactic_id,omitempty"`

	// tactic name
	TacticName string `json:"tactic_name,omitempty"`

	// technique id
	TechniqueID string `json:"technique_id,omitempty"`

	// technique name
	TechniqueName string `json:"technique_name,omitempty"`
}

// Validate validates this domain denormalized threat used mitre
func (m *DomainDenormalizedThreatUsedMitre) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateReports(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDenormalizedThreatUsedMitre) validateReports(formats strfmt.Registry) error {
	if swag.IsZero(m.Reports) { // not required
		return nil
	}

	for i := 0; i < len(m.Reports); i++ {
		if swag.IsZero(m.Reports[i]) { // not required
			continue
		}

		if m.Reports[i] != nil {
			if err := m.Reports[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("reports" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("reports" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this domain denormalized threat used mitre based on the context it is used
func (m *DomainDenormalizedThreatUsedMitre) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateReports(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDenormalizedThreatUsedMitre) contextValidateReports(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Reports); i++ {

		if m.Reports[i] != nil {

			if swag.IsZero(m.Reports[i]) { // not required
				return nil
			}

			if err := m.Reports[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("reports" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("reports" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainDenormalizedThreatUsedMitre) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainDenormalizedThreatUsedMitre) UnmarshalBinary(b []byte) error {
	var res DomainDenormalizedThreatUsedMitre
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
