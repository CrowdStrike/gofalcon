// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DomainAWSAccountV2 domain a w s account v2
//
// swagger:model domain.AWSAccountV2
type DomainAWSAccountV2 struct {

	// created at
	// Required: true
	// Format: date-time
	CreatedAt *strfmt.DateTime `json:"CreatedAt"`

	// deleted at
	// Required: true
	// Format: date-time
	DeletedAt *strfmt.DateTime `json:"DeletedAt"`

	// ID
	// Required: true
	ID *int64 `json:"ID"`

	// updated at
	// Required: true
	// Format: date-time
	UpdatedAt *strfmt.DateTime `json:"UpdatedAt"`

	// 12 digit AWS provided unique identifier for the account.
	AccountID string `json:"account_id,omitempty"`

	// AWS account name
	AccountName string `json:"account_name,omitempty"`

	// account type
	AccountType string `json:"account_type,omitempty"`

	// active regions
	ActiveRegions []string `json:"active_regions"`

	// AWS CloudTrail bucket name to store logs.
	AwsCloudtrailBucketName string `json:"aws_cloudtrail_bucket_name,omitempty"`

	// AWS CloudTrail region.
	AwsCloudtrailRegion string `json:"aws_cloudtrail_region,omitempty"`

	// AWS Eventbus ARN.
	AwsEventbusArn string `json:"aws_eventbus_arn,omitempty"`

	// Permissions status returned via API.
	// Required: true
	AwsPermissionsStatus []*DomainPermission `json:"aws_permissions_status"`

	// behavior assessment enabled
	BehaviorAssessmentEnabled bool `json:"behavior_assessment_enabled,omitempty"`

	// cid
	Cid string `json:"cid,omitempty"`

	// cloud scopes
	CloudScopes []*DomainCloudScope `json:"cloud_scopes"`

	// cloudformation url
	CloudformationURL string `json:"cloudformation_url,omitempty"`

	// conditions
	Conditions []*DomainCondition `json:"conditions"`

	// cspm enabled
	CspmEnabled bool `json:"cspm_enabled,omitempty"`

	// d4c
	D4c *DomainAWSD4CAccountV1 `json:"d4c,omitempty"`

	// d4c migrated
	D4cMigrated bool `json:"d4c_migrated,omitempty"`

	// dspm enabled
	DspmEnabled bool `json:"dspm_enabled,omitempty"`

	// dspm role arn
	DspmRoleArn string `json:"dspm_role_arn,omitempty"`

	// environment
	Environment string `json:"environment,omitempty"`

	// eventbus name
	EventbusName string `json:"eventbus_name,omitempty"`

	// ID assigned for use with cross account IAM role access.
	ExternalID string `json:"external_id,omitempty"`

	// The full arn of the IAM role created in this account to control access.
	IamRoleArn string `json:"iam_role_arn,omitempty"`

	// intermediate role arn
	IntermediateRoleArn string `json:"intermediate_role_arn,omitempty"`

	// inventory filter
	// Required: true
	InventoryFilter []*DomainAWSInventoryFilterSetting `json:"inventory_filter"`

	// Is CSPM Lite enabled.
	IsCspmLite bool `json:"is_cspm_lite,omitempty"`

	// is custom rolename
	// Required: true
	IsCustomRolename *bool `json:"is_custom_rolename"`

	// is master
	IsMaster bool `json:"is_master,omitempty"`

	// Up to 34 character AWS provided unique identifier for the organization.
	OrganizationID string `json:"organization_id,omitempty"`

	// products
	Products []string `json:"products"`

	// remediation cloudformation url
	RemediationCloudformationURL string `json:"remediation_cloudformation_url,omitempty"`

	// remediation region
	RemediationRegion string `json:"remediation_region,omitempty"`

	// remediation tou accepted
	// Format: date-time
	RemediationTouAccepted strfmt.DateTime `json:"remediation_tou_accepted,omitempty"`

	// 12 digit AWS provided unique identifier for the root account (of the organization this account belongs to).
	RootAccountID string `json:"root_account_id,omitempty"`

	// root iam role
	RootIamRole bool `json:"root_iam_role,omitempty"`

	// secondary role arn
	SecondaryRoleArn string `json:"secondary_role_arn,omitempty"`

	// sensor management enabled
	// Required: true
	SensorManagementEnabled *bool `json:"sensor_management_enabled"`

	// settings
	Settings interface{} `json:"settings,omitempty"`

	// Account registration status.
	Status string `json:"status,omitempty"`

	// target ous
	TargetOus []string `json:"target_ous"`

	// use existing cloudtrail
	UseExistingCloudtrail bool `json:"use_existing_cloudtrail,omitempty"`

	// valid
	Valid bool `json:"valid,omitempty"`
}

// Validate validates this domain a w s account v2
func (m *DomainAWSAccountV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeletedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAwsPermissionsStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudScopes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConditions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateD4c(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInventoryFilter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsCustomRolename(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemediationTouAccepted(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSensorManagementEnabled(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainAWSAccountV2) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("CreatedAt", "body", m.CreatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("CreatedAt", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSAccountV2) validateDeletedAt(formats strfmt.Registry) error {

	if err := validate.Required("DeletedAt", "body", m.DeletedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("DeletedAt", "body", "date-time", m.DeletedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSAccountV2) validateID(formats strfmt.Registry) error {

	if err := validate.Required("ID", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSAccountV2) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("UpdatedAt", "body", m.UpdatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("UpdatedAt", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSAccountV2) validateAwsPermissionsStatus(formats strfmt.Registry) error {

	if err := validate.Required("aws_permissions_status", "body", m.AwsPermissionsStatus); err != nil {
		return err
	}

	for i := 0; i < len(m.AwsPermissionsStatus); i++ {
		if swag.IsZero(m.AwsPermissionsStatus[i]) { // not required
			continue
		}

		if m.AwsPermissionsStatus[i] != nil {
			if err := m.AwsPermissionsStatus[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("aws_permissions_status" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("aws_permissions_status" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) validateCloudScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudScopes) { // not required
		return nil
	}

	for i := 0; i < len(m.CloudScopes); i++ {
		if swag.IsZero(m.CloudScopes[i]) { // not required
			continue
		}

		if m.CloudScopes[i] != nil {
			if err := m.CloudScopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) validateConditions(formats strfmt.Registry) error {
	if swag.IsZero(m.Conditions) { // not required
		return nil
	}

	for i := 0; i < len(m.Conditions); i++ {
		if swag.IsZero(m.Conditions[i]) { // not required
			continue
		}

		if m.Conditions[i] != nil {
			if err := m.Conditions[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("conditions" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("conditions" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) validateD4c(formats strfmt.Registry) error {
	if swag.IsZero(m.D4c) { // not required
		return nil
	}

	if m.D4c != nil {
		if err := m.D4c.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("d4c")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("d4c")
			}
			return err
		}
	}

	return nil
}

func (m *DomainAWSAccountV2) validateInventoryFilter(formats strfmt.Registry) error {

	if err := validate.Required("inventory_filter", "body", m.InventoryFilter); err != nil {
		return err
	}

	for i := 0; i < len(m.InventoryFilter); i++ {
		if swag.IsZero(m.InventoryFilter[i]) { // not required
			continue
		}

		if m.InventoryFilter[i] != nil {
			if err := m.InventoryFilter[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("inventory_filter" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("inventory_filter" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) validateIsCustomRolename(formats strfmt.Registry) error {

	if err := validate.Required("is_custom_rolename", "body", m.IsCustomRolename); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSAccountV2) validateRemediationTouAccepted(formats strfmt.Registry) error {
	if swag.IsZero(m.RemediationTouAccepted) { // not required
		return nil
	}

	if err := validate.FormatOf("remediation_tou_accepted", "body", "date-time", m.RemediationTouAccepted.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainAWSAccountV2) validateSensorManagementEnabled(formats strfmt.Registry) error {

	if err := validate.Required("sensor_management_enabled", "body", m.SensorManagementEnabled); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain a w s account v2 based on the context it is used
func (m *DomainAWSAccountV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAwsPermissionsStatus(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCloudScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateConditions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateD4c(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInventoryFilter(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainAWSAccountV2) contextValidateAwsPermissionsStatus(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AwsPermissionsStatus); i++ {

		if m.AwsPermissionsStatus[i] != nil {

			if swag.IsZero(m.AwsPermissionsStatus[i]) { // not required
				return nil
			}

			if err := m.AwsPermissionsStatus[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("aws_permissions_status" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("aws_permissions_status" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) contextValidateCloudScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CloudScopes); i++ {

		if m.CloudScopes[i] != nil {

			if swag.IsZero(m.CloudScopes[i]) { // not required
				return nil
			}

			if err := m.CloudScopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) contextValidateConditions(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Conditions); i++ {

		if m.Conditions[i] != nil {

			if swag.IsZero(m.Conditions[i]) { // not required
				return nil
			}

			if err := m.Conditions[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("conditions" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("conditions" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainAWSAccountV2) contextValidateD4c(ctx context.Context, formats strfmt.Registry) error {

	if m.D4c != nil {

		if swag.IsZero(m.D4c) { // not required
			return nil
		}

		if err := m.D4c.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("d4c")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("d4c")
			}
			return err
		}
	}

	return nil
}

func (m *DomainAWSAccountV2) contextValidateInventoryFilter(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.InventoryFilter); i++ {

		if m.InventoryFilter[i] != nil {

			if swag.IsZero(m.InventoryFilter[i]) { // not required
				return nil
			}

			if err := m.InventoryFilter[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("inventory_filter" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("inventory_filter" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainAWSAccountV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainAWSAccountV2) UnmarshalBinary(b []byte) error {
	var res DomainAWSAccountV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
