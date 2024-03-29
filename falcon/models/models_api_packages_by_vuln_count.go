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

// ModelsAPIPackagesByVulnCount models API packages by vuln count
//
// swagger:model models.APIPackagesByVulnCount
type ModelsAPIPackagesByVulnCount struct {

	// images
	// Required: true
	Images *int64 `json:"images"`

	// package
	// Required: true
	Package *string `json:"package"`

	// packages type
	// Required: true
	PackagesType *string `json:"packages_type"`

	// running images
	// Required: true
	RunningImages *int64 `json:"running_images"`

	// version
	// Required: true
	Version *string `json:"version"`

	// vulnerabilities
	// Required: true
	Vulnerabilities *int32 `json:"vulnerabilities"`
}

// Validate validates this models API packages by vuln count
func (m *ModelsAPIPackagesByVulnCount) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateImages(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePackage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePackagesType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRunningImages(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVulnerabilities(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsAPIPackagesByVulnCount) validateImages(formats strfmt.Registry) error {

	if err := validate.Required("images", "body", m.Images); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPackagesByVulnCount) validatePackage(formats strfmt.Registry) error {

	if err := validate.Required("package", "body", m.Package); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPackagesByVulnCount) validatePackagesType(formats strfmt.Registry) error {

	if err := validate.Required("packages_type", "body", m.PackagesType); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPackagesByVulnCount) validateRunningImages(formats strfmt.Registry) error {

	if err := validate.Required("running_images", "body", m.RunningImages); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPackagesByVulnCount) validateVersion(formats strfmt.Registry) error {

	if err := validate.Required("version", "body", m.Version); err != nil {
		return err
	}

	return nil
}

func (m *ModelsAPIPackagesByVulnCount) validateVulnerabilities(formats strfmt.Registry) error {

	if err := validate.Required("vulnerabilities", "body", m.Vulnerabilities); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models API packages by vuln count based on context it is used
func (m *ModelsAPIPackagesByVulnCount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsAPIPackagesByVulnCount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsAPIPackagesByVulnCount) UnmarshalBinary(b []byte) error {
	var res ModelsAPIPackagesByVulnCount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
