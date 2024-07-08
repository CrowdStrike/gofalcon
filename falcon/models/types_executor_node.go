// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TypesExecutorNode types executor node
//
// swagger:model types.ExecutorNode
type TypesExecutorNode struct {

	// additional header
	AdditionalHeader string `json:"additional_header,omitempty"`

	// current aws arn
	CurrentAwsArn string `json:"current_aws_arn,omitempty"`

	// dashboard url
	DashboardURL string `json:"dashboard_url,omitempty"`

	// id
	ID int64 `json:"id,omitempty"`

	// last health check
	LastHealthCheck int64 `json:"last_health_check,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// organization id
	OrganizationID int64 `json:"organization_id,omitempty"`

	// password
	Password string `json:"password,omitempty"`

	// pod settings
	PodSettings *TypesK8SPodSettings `json:"pod_settings,omitempty"`

	// project id
	ProjectID int64 `json:"project_id,omitempty"`

	// proxy address
	ProxyAddress string `json:"proxy_address,omitempty"`

	// type
	Type string `json:"type,omitempty"`

	// use jobs
	UseJobs bool `json:"useJobs,omitempty"`

	// username
	Username string `json:"username,omitempty"`
}

// Validate validates this types executor node
func (m *TypesExecutorNode) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePodSettings(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesExecutorNode) validatePodSettings(formats strfmt.Registry) error {
	if swag.IsZero(m.PodSettings) { // not required
		return nil
	}

	if m.PodSettings != nil {
		if err := m.PodSettings.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pod_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pod_settings")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this types executor node based on the context it is used
func (m *TypesExecutorNode) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePodSettings(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesExecutorNode) contextValidatePodSettings(ctx context.Context, formats strfmt.Registry) error {

	if m.PodSettings != nil {

		if swag.IsZero(m.PodSettings) { // not required
			return nil
		}

		if err := m.PodSettings.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pod_settings")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pod_settings")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TypesExecutorNode) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesExecutorNode) UnmarshalBinary(b []byte) error {
	var res TypesExecutorNode
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
