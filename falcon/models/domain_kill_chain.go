// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomainKillChain domain kill chain
//
// swagger:model domain.KillChain
type DomainKillChain struct {

	// Free form text describing actions and objectives of the actor
	ActionsAndObjectives string `json:"actions_and_objectives,omitempty"`

	// Free form text describing methods and tools used to communicate with and control an infected machine or network
	CommandAndControl string `json:"command_and_control,omitempty"`

	// Free form text describing malware delivery by actor
	Delivery string `json:"delivery,omitempty"`

	// Comma separated values of vulnerabilities by CVE codes that are exploited by actor
	Exploitation string `json:"exploitation,omitempty"`

	// Free form text describing actor's malware installation on the asset
	Installation string `json:"installation,omitempty"`

	// Legacy field, not used and empty
	Objectives string `json:"objectives,omitempty"`

	// Free form text describing how targets are researched, identified and selected
	Reconnaissance string `json:"reconnaissance,omitempty"`

	// Rich free form text describing actions and objectives of the actor
	RichTextActionsAndObjectives string `json:"rich_text_actions_and_objectives,omitempty"`

	// Rich free form text describing methods and tools used to communicate with and control an infected machine or network
	RichTextCommandAndControl string `json:"rich_text_command_and_control,omitempty"`

	// Rich free form text describing malware delivery by actor
	RichTextDelivery string `json:"rich_text_delivery,omitempty"`

	// Rich text comma separated values of vulnerabilities by CVE codes that are exploited by actor
	RichTextExploitation string `json:"rich_text_exploitation,omitempty"`

	// Rich free form text describing actor's malware installation on the asset
	RichTextInstallation string `json:"rich_text_installation,omitempty"`

	// Legacy field, not used and empty
	RichTextObjectives string `json:"rich_text_objectives,omitempty"`

	// Rich free form text describing how targets are researched, identified and selected
	RichTextReconnaissance string `json:"rich_text_reconnaissance,omitempty"`

	// Rich free form text describing weaponization of the threat/malware (couples exploit with backdoor into deliverable payload)
	RichTextWeaponization string `json:"rich_text_weaponization,omitempty"`

	// Free form text describing weaponization of the threat/malware (couples exploit with backdoor into deliverable payload)
	Weaponization string `json:"weaponization,omitempty"`
}

// Validate validates this domain kill chain
func (m *DomainKillChain) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this domain kill chain based on context it is used
func (m *DomainKillChain) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainKillChain) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainKillChain) UnmarshalBinary(b []byte) error {
	var res DomainKillChain
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
