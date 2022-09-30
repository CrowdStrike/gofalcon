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

// DomainDDOSAttackSource domain d d o s attack source
//
// swagger:model domain.DDOSAttackSource
type DomainDDOSAttackSource struct {

	// The type of attack. One of `Amplification`, `Botnet`, `Other`
	// Required: true
	AttackType *string `json:"attack_type"`

	// The confidence level. One of `Low`, `Medium`, `High`
	// Required: true
	Confidence *string `json:"confidence"`

	// The duration of the attack in seconds
	// Required: true
	Duration *int64 `json:"duration"`

	// The hash over target and date
	// Required: true
	Key *string `json:"key"`

	// The network protocol used. One of `TCP`, `UDP`, `ICMP`, `Other`
	// Required: true
	NetworkProtocol *string `json:"network_protocol"`

	// The protocols used in the attack
	// Required: true
	Protocols []string `json:"protocols"`

	// The number of requests against the target
	// Required: true
	Requests *int64 `json:"requests"`

	// The ISO-8601 date for the attack start time
	// Required: true
	StartTime *string `json:"start_time"`

	// The target's IPv4/6 address or hostname
	// Required: true
	Target *string `json:"target"`

	// target details
	// Required: true
	TargetDetails *DomainDDOSTargetDetails `json:"target_details"`

	// The target's domain
	// Required: true
	TargetDomain *string `json:"target_domain"`

	// The target's IPv4/6 address
	// Required: true
	TargetIP *string `json:"target_ip"`

	// List of ports where the attack took place
	// Required: true
	TargetPorts []int64 `json:"target_ports"`
}

// Validate validates this domain d d o s attack source
func (m *DomainDDOSAttackSource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttackType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConfidence(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNetworkProtocol(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProtocols(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequests(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTarget(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetDetails(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetDomain(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetIP(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetPorts(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDDOSAttackSource) validateAttackType(formats strfmt.Registry) error {

	if err := validate.Required("attack_type", "body", m.AttackType); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateConfidence(formats strfmt.Registry) error {

	if err := validate.Required("confidence", "body", m.Confidence); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateDuration(formats strfmt.Registry) error {

	if err := validate.Required("duration", "body", m.Duration); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateKey(formats strfmt.Registry) error {

	if err := validate.Required("key", "body", m.Key); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateNetworkProtocol(formats strfmt.Registry) error {

	if err := validate.Required("network_protocol", "body", m.NetworkProtocol); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateProtocols(formats strfmt.Registry) error {

	if err := validate.Required("protocols", "body", m.Protocols); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateRequests(formats strfmt.Registry) error {

	if err := validate.Required("requests", "body", m.Requests); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateStartTime(formats strfmt.Registry) error {

	if err := validate.Required("start_time", "body", m.StartTime); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateTarget(formats strfmt.Registry) error {

	if err := validate.Required("target", "body", m.Target); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateTargetDetails(formats strfmt.Registry) error {

	if err := validate.Required("target_details", "body", m.TargetDetails); err != nil {
		return err
	}

	if m.TargetDetails != nil {
		if err := m.TargetDetails.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("target_details")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("target_details")
			}
			return err
		}
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateTargetDomain(formats strfmt.Registry) error {

	if err := validate.Required("target_domain", "body", m.TargetDomain); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateTargetIP(formats strfmt.Registry) error {

	if err := validate.Required("target_ip", "body", m.TargetIP); err != nil {
		return err
	}

	return nil
}

func (m *DomainDDOSAttackSource) validateTargetPorts(formats strfmt.Registry) error {

	if err := validate.Required("target_ports", "body", m.TargetPorts); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain d d o s attack source based on the context it is used
func (m *DomainDDOSAttackSource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateTargetDetails(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainDDOSAttackSource) contextValidateTargetDetails(ctx context.Context, formats strfmt.Registry) error {

	if m.TargetDetails != nil {
		if err := m.TargetDetails.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("target_details")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("target_details")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainDDOSAttackSource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainDDOSAttackSource) UnmarshalBinary(b []byte) error {
	var res DomainDDOSAttackSource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
