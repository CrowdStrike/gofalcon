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
	"github.com/go-openapi/validate"
)

// ModelsAPIImageVulnerabilitiesSummary models API image vulnerabilities summary
//
// swagger:model models.APIImageVulnerabilitiesSummary
type ModelsAPIImageVulnerabilitiesSummary struct {

	// app packages with vulnerabilities
	// Required: true
	AppPackagesWithVulnerabilities *int32 `json:"app_packages_with_vulnerabilities"`

	// app vuln by severity
	// Required: true
	AppVulnBySeverity []*ModelsAPIVulnCountBySeverity `json:"app_vuln_by_severity"`

	// image vuln by severity
	// Required: true
	ImageVulnBySeverity []*ModelsAPIVulnCountBySeverity `json:"image_vuln_by_severity"`

	// layers with vulnerabilities
	// Required: true
	LayersWithVulnerabilities *int32 `json:"layers_with_vulnerabilities"`

	// os packages with vulnerabilities
	// Required: true
	OsPackagesWithVulnerabilities *int32 `json:"os_packages_with_vulnerabilities"`

	// os vuln by severity
	// Required: true
	OsVulnBySeverity []*ModelsAPIVulnCountBySeverity `json:"os_vuln_by_severity"`

	// total app packages
	// Required: true
	TotalAppPackages *int32 `json:"total_app_packages"`

	// total os packages
	// Required: true
	TotalOsPackages *int32 `json:"total_os_packages"`

	// total vulnerabilities
	// Required: true
	TotalVulnerabilities *int32 `json:"total_vulnerabilities"`
}

// Validate validates this models API image vulnerabilities summary
func (m *ModelsAPIImageVulnerabilitiesSummary) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAppPackagesWithVulnerabilities(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAppVulnBySeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateImageVulnBySeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLayersWithVulnerabilities(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOsPackagesWithVulnerabilities(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOsVulnBySeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalAppPackages(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalOsPackages(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalVulnerabilities(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateAppPackagesWithVulnerabilities(formats strfmt.Registry) error {

	if err := validate.Required("app_packages_with_vulnerabilities", "body", m.AppPackagesWithVulnerabilities); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateAppVulnBySeverity(formats strfmt.Registry) error {

	if err := validate.Required("app_vuln_by_severity", "body", m.AppVulnBySeverity); err != nil {
		return err
	}

	for i := 0; i < len(m.AppVulnBySeverity); i++ {
		if swag.IsZero(m.AppVulnBySeverity[i]) { // not required
			continue
		}

		if m.AppVulnBySeverity[i] != nil {
			if err := m.AppVulnBySeverity[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("app_vuln_by_severity" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("app_vuln_by_severity" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateImageVulnBySeverity(formats strfmt.Registry) error {

	if err := validate.Required("image_vuln_by_severity", "body", m.ImageVulnBySeverity); err != nil {
		return err
	}

	for i := 0; i < len(m.ImageVulnBySeverity); i++ {
		if swag.IsZero(m.ImageVulnBySeverity[i]) { // not required
			continue
		}

		if m.ImageVulnBySeverity[i] != nil {
			if err := m.ImageVulnBySeverity[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("image_vuln_by_severity" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("image_vuln_by_severity" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateLayersWithVulnerabilities(formats strfmt.Registry) error {

	if err := validate.Required("layers_with_vulnerabilities", "body", m.LayersWithVulnerabilities); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateOsPackagesWithVulnerabilities(formats strfmt.Registry) error {

	if err := validate.Required("os_packages_with_vulnerabilities", "body", m.OsPackagesWithVulnerabilities); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateOsVulnBySeverity(formats strfmt.Registry) error {

	if err := validate.Required("os_vuln_by_severity", "body", m.OsVulnBySeverity); err != nil {
		return err
	}

	for i := 0; i < len(m.OsVulnBySeverity); i++ {
		if swag.IsZero(m.OsVulnBySeverity[i]) { // not required
			continue
		}

		if m.OsVulnBySeverity[i] != nil {
			if err := m.OsVulnBySeverity[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("os_vuln_by_severity" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("os_vuln_by_severity" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateTotalAppPackages(formats strfmt.Registry) error {

	if err := validate.Required("total_app_packages", "body", m.TotalAppPackages); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateTotalOsPackages(formats strfmt.Registry) error {

	if err := validate.Required("total_os_packages", "body", m.TotalOsPackages); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) validateTotalVulnerabilities(formats strfmt.Registry) error {

	if err := validate.Required("total_vulnerabilities", "body", m.TotalVulnerabilities); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this models API image vulnerabilities summary based on the context it is used
func (m *ModelsAPIImageVulnerabilitiesSummary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAppVulnBySeverity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateImageVulnBySeverity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOsVulnBySeverity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) contextValidateAppVulnBySeverity(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AppVulnBySeverity); i++ {

		if m.AppVulnBySeverity[i] != nil {

			if swag.IsZero(m.AppVulnBySeverity[i]) { // not required
				return nil
			}

			if err := m.AppVulnBySeverity[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("app_vuln_by_severity" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("app_vuln_by_severity" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) contextValidateImageVulnBySeverity(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ImageVulnBySeverity); i++ {

		if m.ImageVulnBySeverity[i] != nil {

			if swag.IsZero(m.ImageVulnBySeverity[i]) { // not required
				return nil
			}

			if err := m.ImageVulnBySeverity[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("image_vuln_by_severity" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("image_vuln_by_severity" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ModelsAPIImageVulnerabilitiesSummary) contextValidateOsVulnBySeverity(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OsVulnBySeverity); i++ {

		if m.OsVulnBySeverity[i] != nil {

			if swag.IsZero(m.OsVulnBySeverity[i]) { // not required
				return nil
			}

			if err := m.OsVulnBySeverity[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("os_vuln_by_severity" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("os_vuln_by_severity" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModelsAPIImageVulnerabilitiesSummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsAPIImageVulnerabilitiesSummary) UnmarshalBinary(b []byte) error {
	var res ModelsAPIImageVulnerabilitiesSummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
