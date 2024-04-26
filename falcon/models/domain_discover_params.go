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

// DomainDiscoverParams domain discover params
//
// swagger:model domain.DiscoverParams
type DomainDiscoverParams struct {

	// application filters
	// Required: true
	ApplicationFilters *string `json:"application_filters"`

	// application group id
	// Required: true
	ApplicationGroupID *string `json:"application_group_id"`

	// application vendors
	// Required: true
	ApplicationVendors *string `json:"application_vendors"`

	// inline app filter
	// Required: true
	InlineAppFilter *string `json:"inline_app_filter"`

	// requirement criteria
	// Required: true
	RequirementCriteria *string `json:"requirement_criteria"`
}

// Validate validates this domain discover params
func (m *DomainDiscoverParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApplicationFilters(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateApplicationGroupID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateApplicationVendors(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInlineAppFilter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequirementCriteria(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDiscoverParams) validateApplicationFilters(formats strfmt.Registry) error {

	if err := validate.Required("application_filters", "body", m.ApplicationFilters); err != nil {
		return err
	}

	return nil
}

func (m *DomainDiscoverParams) validateApplicationGroupID(formats strfmt.Registry) error {

	if err := validate.Required("application_group_id", "body", m.ApplicationGroupID); err != nil {
		return err
	}

	return nil
}

func (m *DomainDiscoverParams) validateApplicationVendors(formats strfmt.Registry) error {

	if err := validate.Required("application_vendors", "body", m.ApplicationVendors); err != nil {
		return err
	}

	return nil
}

func (m *DomainDiscoverParams) validateInlineAppFilter(formats strfmt.Registry) error {

	if err := validate.Required("inline_app_filter", "body", m.InlineAppFilter); err != nil {
		return err
	}

	return nil
}

func (m *DomainDiscoverParams) validateRequirementCriteria(formats strfmt.Registry) error {

	if err := validate.Required("requirement_criteria", "body", m.RequirementCriteria); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain discover params based on context it is used
func (m *DomainDiscoverParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainDiscoverParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainDiscoverParams) UnmarshalBinary(b []byte) error {
	var res DomainDiscoverParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
