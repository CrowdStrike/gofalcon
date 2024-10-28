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

// DomainReportParams domain report params
//
// swagger:model domain.ReportParams
type DomainReportParams struct {

	// columns
	// Required: true
	Columns []string `json:"columns"`

	// dashboard id
	// Required: true
	DashboardID *string `json:"dashboard_id"`

	// dashboard visibility
	// Required: true
	DashboardVisibility *string `json:"dashboard_visibility"`

	// filter
	// Required: true
	Filter *string `json:"filter"`

	// filter display
	// Required: true
	FilterDisplay *string `json:"filter_display"`

	// filter ui
	// Required: true
	FilterUI *string `json:"filter_ui"`

	// format
	// Required: true
	Format *string `json:"format"`

	// report type options
	ReportTypeOptions map[string]string `json:"report_type_options,omitempty"`

	// sort
	// Required: true
	Sort *string `json:"sort"`

	// spotlight params
	SpotlightParams *DomainSpotlightParams `json:"spotlight_params,omitempty"`
}

// Validate validates this domain report params
func (m *DomainReportParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateColumns(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDashboardID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDashboardVisibility(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilterDisplay(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilterUI(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSort(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSpotlightParams(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainReportParams) validateColumns(formats strfmt.Registry) error {

	if err := validate.Required("columns", "body", m.Columns); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateDashboardID(formats strfmt.Registry) error {

	if err := validate.Required("dashboard_id", "body", m.DashboardID); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateDashboardVisibility(formats strfmt.Registry) error {

	if err := validate.Required("dashboard_visibility", "body", m.DashboardVisibility); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateFilter(formats strfmt.Registry) error {

	if err := validate.Required("filter", "body", m.Filter); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateFilterDisplay(formats strfmt.Registry) error {

	if err := validate.Required("filter_display", "body", m.FilterDisplay); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateFilterUI(formats strfmt.Registry) error {

	if err := validate.Required("filter_ui", "body", m.FilterUI); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateFormat(formats strfmt.Registry) error {

	if err := validate.Required("format", "body", m.Format); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateSort(formats strfmt.Registry) error {

	if err := validate.Required("sort", "body", m.Sort); err != nil {
		return err
	}

	return nil
}

func (m *DomainReportParams) validateSpotlightParams(formats strfmt.Registry) error {
	if swag.IsZero(m.SpotlightParams) { // not required
		return nil
	}

	if m.SpotlightParams != nil {
		if err := m.SpotlightParams.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("spotlight_params")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("spotlight_params")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domain report params based on the context it is used
func (m *DomainReportParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSpotlightParams(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainReportParams) contextValidateSpotlightParams(ctx context.Context, formats strfmt.Registry) error {

	if m.SpotlightParams != nil {

		if swag.IsZero(m.SpotlightParams) { // not required
			return nil
		}

		if err := m.SpotlightParams.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("spotlight_params")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("spotlight_params")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainReportParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainReportParams) UnmarshalBinary(b []byte) error {
	var res DomainReportParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
