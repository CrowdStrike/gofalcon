// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesAwsLoadBalancerReasonTag types aws load balancer reason tag
//
// swagger:model types.AwsLoadBalancerReasonTag
type TypesAwsLoadBalancerReasonTag struct {

	// dns name
	DNSName string `json:"dnsName,omitempty"`

	// reason
	Reason string `json:"reason,omitempty"`
}

// Validate validates this types aws load balancer reason tag
func (m *TypesAwsLoadBalancerReasonTag) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this types aws load balancer reason tag based on context it is used
func (m *TypesAwsLoadBalancerReasonTag) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TypesAwsLoadBalancerReasonTag) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesAwsLoadBalancerReasonTag) UnmarshalBinary(b []byte) error {
	var res TypesAwsLoadBalancerReasonTag
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
