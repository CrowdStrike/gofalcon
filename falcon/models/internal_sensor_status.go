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

// InternalSensorStatus internal sensor status
//
// swagger:model internal.SensorStatus
type InternalSensorStatus struct {

	// agent version
	AgentVersion string `json:"agent_version,omitempty"`

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// device id
	// Required: true
	DeviceID *string `json:"device_id"`

	// heartbeat time
	HeartbeatTime int64 `json:"heartbeat_time,omitempty"`

	// hostname
	Hostname string `json:"hostname,omitempty"`

	// idp policy id
	IdpPolicyID string `json:"idp_policy_id,omitempty"`

	// idp policy name
	IdpPolicyName string `json:"idp_policy_name,omitempty"`

	// kerberos config
	KerberosConfig string `json:"kerberos_config,omitempty"`

	// ldap config
	LdapConfig string `json:"ldap_config,omitempty"`

	// ldaps config
	LdapsConfig string `json:"ldaps_config,omitempty"`

	// local ip
	LocalIP string `json:"local_ip,omitempty"`

	// machine domain
	MachineDomain string `json:"machine_domain,omitempty"`

	// ntlm config
	NtlmConfig string `json:"ntlm_config,omitempty"`

	// os version
	OsVersion string `json:"os_version,omitempty"`

	// rdp to dc config
	RdpToDcConfig string `json:"rdp_to_dc_config,omitempty"`

	// smb to dc config
	SmbToDcConfig string `json:"smb_to_dc_config,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// status causes
	StatusCauses []string `json:"status_causes"`

	// ti enabled
	TiEnabled string `json:"ti_enabled,omitempty"`
}

// Validate validates this internal sensor status
func (m *InternalSensorStatus) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InternalSensorStatus) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *InternalSensorStatus) validateDeviceID(formats strfmt.Registry) error {

	if err := validate.Required("device_id", "body", m.DeviceID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this internal sensor status based on context it is used
func (m *InternalSensorStatus) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *InternalSensorStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InternalSensorStatus) UnmarshalBinary(b []byte) error {
	var res InternalSensorStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
