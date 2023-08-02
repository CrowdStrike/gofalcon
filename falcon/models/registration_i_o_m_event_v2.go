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

// RegistrationIOMEventV2 registration i o m event v2
//
// swagger:model registration.IOMEventV2
type RegistrationIOMEventV2 struct {

	// account id
	// Required: true
	AccountID *string `json:"account_id"`

	// account name
	// Required: true
	AccountName *string `json:"account_name"`

	// agent id
	AgentID string `json:"agent_id,omitempty"`

	// azure tenant id
	AzureTenantID string `json:"azure_tenant_id,omitempty"`

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// cloud provider
	// Required: true
	CloudProvider *string `json:"cloud_provider"`

	// custom policy id
	CustomPolicyID int32 `json:"custom_policy_id,omitempty"`

	// finding
	// Required: true
	Finding interface{} `json:"finding"`

	// id
	// Required: true
	ID *string `json:"id"`

	// is managed
	IsManaged bool `json:"is_managed,omitempty"`

	// policy id
	PolicyID int32 `json:"policy_id,omitempty"`

	// policy statement
	// Required: true
	PolicyStatement *string `json:"policy_statement"`

	// policy type
	PolicyType string `json:"policy_type,omitempty"`

	// region
	// Required: true
	Region *string `json:"region"`

	// report date time
	// Required: true
	// Format: date-time
	ReportDateTime *strfmt.DateTime `json:"report_date_time"`

	// resource attributes
	// Required: true
	ResourceAttributes interface{} `json:"resource_attributes"`

	// resource create time
	// Required: true
	// Format: date-time
	ResourceCreateTime *strfmt.DateTime `json:"resource_create_time"`

	// resource id
	// Required: true
	ResourceID *string `json:"resource_id"`

	// resource id type
	// Required: true
	ResourceIDType *string `json:"resource_id_type"`

	// resource url
	// Required: true
	ResourceURL *string `json:"resource_url"`

	// resource uuid
	// Required: true
	ResourceUUID *string `json:"resource_uuid"`

	// scan id
	ScanID string `json:"scan_id,omitempty"`

	// scan time
	// Required: true
	// Format: date-time
	ScanTime *strfmt.DateTime `json:"scan_time"`

	// service
	// Required: true
	Service *string `json:"service"`

	// severity
	// Required: true
	Severity *string `json:"severity"`

	// status
	// Required: true
	Status *string `json:"status"`

	// tags
	// Required: true
	Tags map[string]string `json:"tags"`

	// vm id
	VMID string `json:"vm_id,omitempty"`
}

// Validate validates this registration i o m event v2
func (m *RegistrationIOMEventV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAccountName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFinding(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyStatement(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRegion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReportDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceCreateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceIDType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceURL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceUUID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScanTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationIOMEventV2) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("account_id", "body", m.AccountID); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateAccountName(formats strfmt.Registry) error {

	if err := validate.Required("account_name", "body", m.AccountName); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateCloudProvider(formats strfmt.Registry) error {

	if err := validate.Required("cloud_provider", "body", m.CloudProvider); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateFinding(formats strfmt.Registry) error {

	if m.Finding == nil {
		return errors.Required("finding", "body", nil)
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validatePolicyStatement(formats strfmt.Registry) error {

	if err := validate.Required("policy_statement", "body", m.PolicyStatement); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateRegion(formats strfmt.Registry) error {

	if err := validate.Required("region", "body", m.Region); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateReportDateTime(formats strfmt.Registry) error {

	if err := validate.Required("report_date_time", "body", m.ReportDateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("report_date_time", "body", "date-time", m.ReportDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateResourceAttributes(formats strfmt.Registry) error {

	if m.ResourceAttributes == nil {
		return errors.Required("resource_attributes", "body", nil)
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateResourceCreateTime(formats strfmt.Registry) error {

	if err := validate.Required("resource_create_time", "body", m.ResourceCreateTime); err != nil {
		return err
	}

	if err := validate.FormatOf("resource_create_time", "body", "date-time", m.ResourceCreateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateResourceID(formats strfmt.Registry) error {

	if err := validate.Required("resource_id", "body", m.ResourceID); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateResourceIDType(formats strfmt.Registry) error {

	if err := validate.Required("resource_id_type", "body", m.ResourceIDType); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateResourceURL(formats strfmt.Registry) error {

	if err := validate.Required("resource_url", "body", m.ResourceURL); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateResourceUUID(formats strfmt.Registry) error {

	if err := validate.Required("resource_uuid", "body", m.ResourceUUID); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateScanTime(formats strfmt.Registry) error {

	if err := validate.Required("scan_time", "body", m.ScanTime); err != nil {
		return err
	}

	if err := validate.FormatOf("scan_time", "body", "date-time", m.ScanTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateService(formats strfmt.Registry) error {

	if err := validate.Required("service", "body", m.Service); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateSeverity(formats strfmt.Registry) error {

	if err := validate.Required("severity", "body", m.Severity); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationIOMEventV2) validateTags(formats strfmt.Registry) error {

	if err := validate.Required("tags", "body", m.Tags); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this registration i o m event v2 based on context it is used
func (m *RegistrationIOMEventV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RegistrationIOMEventV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegistrationIOMEventV2) UnmarshalBinary(b []byte) error {
	var res RegistrationIOMEventV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
