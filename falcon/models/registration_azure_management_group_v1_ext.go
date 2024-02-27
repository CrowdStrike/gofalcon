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

// RegistrationAzureManagementGroupV1Ext registration azure management group v1 ext
//
// swagger:model registration.AzureManagementGroupV1Ext
type RegistrationAzureManagementGroupV1Ext struct {

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

	// Azure Management Group ID.
	// Required: true
	AzureManagementGroupID *string `json:"azure_management_group_id"`

	// Azure Management Group Name.
	AzureManagementGroupName string `json:"azure_management_group_name,omitempty"`

	// Permissions status returned via API.
	AzurePermissionsStatus []*DomainPermission `json:"azure_permissions_status"`

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// client id
	ClientID string `json:"client_id,omitempty"`

	// conditions
	Conditions []*DomainCondition `json:"conditions"`

	// credentials end date
	// Format: date-time
	CredentialsEndDate strfmt.DateTime `json:"credentials_end_date,omitempty"`

	// credentials type
	CredentialsType string `json:"credentials_type,omitempty"`

	// Default Azure Subscription ID to provision shared IOA infrastructure.
	DefaultSubscriptionID string `json:"default_subscription_id,omitempty"`

	// object id
	ObjectID string `json:"object_id,omitempty"`

	// public certificate
	PublicCertificate string `json:"public_certificate,omitempty"`

	// public certificate raw
	PublicCertificateRaw string `json:"public_certificate_raw,omitempty"`

	// role assignments
	RoleAssignments []*DomainAzureManagementGroupRoleAssignment `json:"role_assignments"`

	// Account registration status.
	Status string `json:"status,omitempty"`

	// Azure Tenant ID to use.
	// Required: true
	TenantID *string `json:"tenant_id"`

	// years valid
	YearsValid int64 `json:"years_valid,omitempty"`
}

// Validate validates this registration azure management group v1 ext
func (m *RegistrationAzureManagementGroupV1Ext) Validate(formats strfmt.Registry) error {
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

	if err := m.validateAzureManagementGroupID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAzurePermissionsStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConditions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCredentialsEndDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRoleAssignments(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("CreatedAt", "body", m.CreatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("CreatedAt", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateDeletedAt(formats strfmt.Registry) error {

	if err := validate.Required("DeletedAt", "body", m.DeletedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("DeletedAt", "body", "date-time", m.DeletedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateID(formats strfmt.Registry) error {

	if err := validate.Required("ID", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("UpdatedAt", "body", m.UpdatedAt); err != nil {
		return err
	}

	if err := validate.FormatOf("UpdatedAt", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateAzureManagementGroupID(formats strfmt.Registry) error {

	if err := validate.Required("azure_management_group_id", "body", m.AzureManagementGroupID); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateAzurePermissionsStatus(formats strfmt.Registry) error {
	if swag.IsZero(m.AzurePermissionsStatus) { // not required
		return nil
	}

	for i := 0; i < len(m.AzurePermissionsStatus); i++ {
		if swag.IsZero(m.AzurePermissionsStatus[i]) { // not required
			continue
		}

		if m.AzurePermissionsStatus[i] != nil {
			if err := m.AzurePermissionsStatus[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("azure_permissions_status" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("azure_permissions_status" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateConditions(formats strfmt.Registry) error {
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

func (m *RegistrationAzureManagementGroupV1Ext) validateCredentialsEndDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CredentialsEndDate) { // not required
		return nil
	}

	if err := validate.FormatOf("credentials_end_date", "body", "date-time", m.CredentialsEndDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateRoleAssignments(formats strfmt.Registry) error {
	if swag.IsZero(m.RoleAssignments) { // not required
		return nil
	}

	for i := 0; i < len(m.RoleAssignments); i++ {
		if swag.IsZero(m.RoleAssignments[i]) { // not required
			continue
		}

		if m.RoleAssignments[i] != nil {
			if err := m.RoleAssignments[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("role_assignments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("role_assignments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) validateTenantID(formats strfmt.Registry) error {

	if err := validate.Required("tenant_id", "body", m.TenantID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this registration azure management group v1 ext based on the context it is used
func (m *RegistrationAzureManagementGroupV1Ext) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAzurePermissionsStatus(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateConditions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRoleAssignments(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) contextValidateAzurePermissionsStatus(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AzurePermissionsStatus); i++ {

		if m.AzurePermissionsStatus[i] != nil {

			if swag.IsZero(m.AzurePermissionsStatus[i]) { // not required
				return nil
			}

			if err := m.AzurePermissionsStatus[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("azure_permissions_status" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("azure_permissions_status" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RegistrationAzureManagementGroupV1Ext) contextValidateConditions(ctx context.Context, formats strfmt.Registry) error {

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

func (m *RegistrationAzureManagementGroupV1Ext) contextValidateRoleAssignments(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RoleAssignments); i++ {

		if m.RoleAssignments[i] != nil {

			if swag.IsZero(m.RoleAssignments[i]) { // not required
				return nil
			}

			if err := m.RoleAssignments[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("role_assignments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("role_assignments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *RegistrationAzureManagementGroupV1Ext) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegistrationAzureManagementGroupV1Ext) UnmarshalBinary(b []byte) error {
	var res RegistrationAzureManagementGroupV1Ext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
