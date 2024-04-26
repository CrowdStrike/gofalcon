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

// SadomainCreateRuleRequestV1 sadomain create rule request v1
//
// swagger:model sadomain.CreateRuleRequestV1
type SadomainCreateRuleRequestV1 struct {

	// Monitor only for breach data. Must be accompanied by breach_monitoring_enabled:true.
	// Required: true
	BreachMonitorOnly *bool `json:"breach_monitor_only"`

	// Whether to monitor for breach data. Available only for `Company Domains` and `Email addresses` rule topics. When enabled, ownership of the monitored domains or emails is required
	// Required: true
	BreachMonitoringEnabled *bool `json:"breach_monitoring_enabled"`

	// The FQL filter to be used for searching
	// Required: true
	Filter *string `json:"filter"`

	// The name of a given rule
	// Required: true
	Name *string `json:"name"`

	// If the rule was generated based on a template, the id of the template
	// Required: true
	OriginatingTemplateID *string `json:"originating_template_id"`

	// The permissions for a given rule which specifies the rule's access by other users. Possible values: [`public`, `private`]
	// Required: true
	Permissions *string `json:"permissions"`

	// The priority for a given rule. Possible values: [`low`, `medium`, `high`]
	// Required: true
	Priority *string `json:"priority"`

	// Whether to monitor for substring matches. Only available for the `Typosquatting` topic.
	// Required: true
	SubstringMatchingEnabled *bool `json:"substring_matching_enabled"`

	// The topic of a given rule. Possible values: [`SA_BRAND_PRODUCT`, `SA_VIP`, `SA_THIRD_PARTY`, `SA_IP`, `SA_CVE`, `SA_BIN`, `SA_DOMAIN`, `SA_EMAIL`, `SA_ALIAS`, `SA_AUTHOR`, `SA_CUSTOM`, `SA_TYPOSQUATTING`]
	// Required: true
	Topic *string `json:"topic"`
}

// Validate validates this sadomain create rule request v1
func (m *SadomainCreateRuleRequestV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBreachMonitorOnly(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBreachMonitoringEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOriginatingTemplateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePriority(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubstringMatchingEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTopic(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SadomainCreateRuleRequestV1) validateBreachMonitorOnly(formats strfmt.Registry) error {

	if err := validate.Required("breach_monitor_only", "body", m.BreachMonitorOnly); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validateBreachMonitoringEnabled(formats strfmt.Registry) error {

	if err := validate.Required("breach_monitoring_enabled", "body", m.BreachMonitoringEnabled); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validateFilter(formats strfmt.Registry) error {

	if err := validate.Required("filter", "body", m.Filter); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validateOriginatingTemplateID(formats strfmt.Registry) error {

	if err := validate.Required("originating_template_id", "body", m.OriginatingTemplateID); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validatePermissions(formats strfmt.Registry) error {

	if err := validate.Required("permissions", "body", m.Permissions); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validatePriority(formats strfmt.Registry) error {

	if err := validate.Required("priority", "body", m.Priority); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validateSubstringMatchingEnabled(formats strfmt.Registry) error {

	if err := validate.Required("substring_matching_enabled", "body", m.SubstringMatchingEnabled); err != nil {
		return err
	}

	return nil
}

func (m *SadomainCreateRuleRequestV1) validateTopic(formats strfmt.Registry) error {

	if err := validate.Required("topic", "body", m.Topic); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this sadomain create rule request v1 based on context it is used
func (m *SadomainCreateRuleRequestV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SadomainCreateRuleRequestV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SadomainCreateRuleRequestV1) UnmarshalBinary(b []byte) error {
	var res SadomainCreateRuleRequestV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
