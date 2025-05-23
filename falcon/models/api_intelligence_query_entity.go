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

// APIIntelligenceQueryEntity api intelligence query entity
//
// swagger:model api.IntelligenceQueryEntity
type APIIntelligenceQueryEntity struct {

	// adversaries
	Adversaries []string `json:"adversaries"`

	// content
	Content string `json:"content,omitempty"`

	// created at
	// Required: true
	// Format: date-time
	CreatedAt *strfmt.DateTime `json:"created_at"`

	// depends on
	DependsOn []string `json:"depends_on"`

	// description
	Description string `json:"description,omitempty"`

	// Field only available for Counter Adversary Elite Customers
	EliteAnalystNotes string `json:"elite_analyst_notes,omitempty"`

	// Field only available for Counter Adversary Elite Customers
	EliteQueryExplainer string `json:"elite_query_explainer,omitempty"`

	// environment
	Environment []string `json:"environment"`

	// has elite analyst notes
	// Required: true
	HasEliteAnalystNotes *bool `json:"has_elite_analyst_notes"`

	// has elite query explainer
	// Required: true
	HasEliteQueryExplainer *bool `json:"has_elite_query_explainer"`

	// id
	// Required: true
	ID *string `json:"id"`

	// kill chain
	KillChain []string `json:"kill_chain"`

	// language
	// Required: true
	Language *string `json:"language"`

	// last updated at
	// Required: true
	// Format: date-time
	LastUpdatedAt *strfmt.DateTime `json:"last_updated_at"`

	// malware families
	MalwareFamilies []string `json:"malware_families"`

	// mitre technique ids
	MitreTechniqueIds []string `json:"mitre_technique_ids"`

	// name
	// Required: true
	Name *string `json:"name"`

	// provider
	// Required: true
	Provider *string `json:"provider"`

	// relates to community alias
	RelatesToCommunityAlias []string `json:"relates_to_community_alias"`

	// reports
	Reports []string `json:"reports"`

	// reports count
	// Required: true
	ReportsCount *int32 `json:"reports_count"`

	// subscriptions
	Subscriptions []string `json:"subscriptions"`

	// type
	// Required: true
	Type *string `json:"type"`

	// version
	// Required: true
	Version *string `json:"version"`
}

// Validate validates this api intelligence query entity
func (m *APIIntelligenceQueryEntity) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHasEliteAnalystNotes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHasEliteQueryExplainer(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLanguage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReportsCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVersion(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIIntelligenceQueryEntity) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", m.CreatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateHasEliteAnalystNotes(formats strfmt.Registry) error {

	if err := validate.Required("has_elite_analyst_notes", "body", m.HasEliteAnalystNotes); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateHasEliteQueryExplainer(formats strfmt.Registry) error {

	if err := validate.Required("has_elite_query_explainer", "body", m.HasEliteQueryExplainer); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateLanguage(formats strfmt.Registry) error {

	if err := validate.Required("language", "body", m.Language); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateLastUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("last_updated_at", "body", m.LastUpdatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("last_updated_at", "body", "date-time", m.LastUpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateProvider(formats strfmt.Registry) error {

	if err := validate.Required("provider", "body", m.Provider); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateReportsCount(formats strfmt.Registry) error {

	if err := validate.Required("reports_count", "body", m.ReportsCount); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *APIIntelligenceQueryEntity) validateVersion(formats strfmt.Registry) error {

	if err := validate.Required("version", "body", m.Version); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this api intelligence query entity based on context it is used
func (m *APIIntelligenceQueryEntity) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIIntelligenceQueryEntity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIIntelligenceQueryEntity) UnmarshalBinary(b []byte) error {
	var res APIIntelligenceQueryEntity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
