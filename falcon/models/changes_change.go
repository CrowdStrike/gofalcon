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

// ChangesChange changes change
//
// swagger:model changes.Change
type ChangesChange struct {

	// action timestamp
	// Required: true
	ActionTimestamp *string `json:"action_timestamp"`

	// Possible values: UNKNOWN, CREATE, WRITE, DELETE, SET, RENAME.
	// Required: true
	ActionType *string `json:"action_type"`

	// aid
	// Required: true
	Aid *string `json:"aid"`

	// attributes
	Attributes []*ChangesAttribute `json:"attributes"`

	// cid
	// Required: true
	Cid *string `json:"cid"`

	// command line
	// Required: true
	CommandLine *string `json:"command_line"`

	// diff
	Diff *ChangesDiff `json:"diff,omitempty"`

	// entity path
	// Required: true
	EntityPath *string `json:"entity_path"`

	// entity path new
	EntityPathNew string `json:"entity_path_new,omitempty"`

	// Possible values: UNKNOWN, FILE, DIR, REGKEY,  REGVAL.
	// Required: true
	EntityType *string `json:"entity_type"`

	// file size
	// Required: true
	FileSize *int64 `json:"file_size"`

	// grandparent process image file name
	GrandparentProcessImageFileName string `json:"grandparent_process_image_file_name,omitempty"`

	// host
	Host *ChangesHost `json:"host,omitempty"`

	// id
	// Required: true
	ID *string `json:"id"`

	// ingestion timestamp
	// Required: true
	IngestionTimestamp *string `json:"ingestion_timestamp"`

	// is from different mount namespace
	// Required: true
	IsFromDifferentMountNamespace *bool `json:"is_from_different_mount_namespace"`

	// is suppressed
	// Required: true
	IsSuppressed *bool `json:"is_suppressed"`

	// oci container id
	OciContainerID string `json:"oci_container_id,omitempty"`

	// parent process image file name
	ParentProcessImageFileName string `json:"parent_process_image_file_name,omitempty"`

	// permissions
	Permissions *ChangesPermissions `json:"permissions,omitempty"`

	// permissions lin
	PermissionsLin *ChangesPermissionsLin `json:"permissions_lin,omitempty"`

	// permissions mac
	PermissionsMac *ChangesPermissionsMac `json:"permissions_mac,omitempty"`

	// platform name
	// Required: true
	PlatformName *string `json:"platform_name"`

	// policy
	Policy *ChangesPolicy `json:"policy,omitempty"`

	// prevalence
	Prevalence *ChangesPrevalence `json:"prevalence,omitempty"`

	// process id
	// Required: true
	ProcessID *string `json:"process_id"`

	// process image file name
	// Required: true
	ProcessImageFileName *string `json:"process_image_file_name"`

	// real user id
	RealUserID string `json:"real_user_id,omitempty"`

	// Possible values: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL
	// Required: true
	Severity *string `json:"severity"`

	// tags
	Tags []*ChangesTag `json:"tags"`

	// user id
	// Required: true
	UserID *string `json:"user_id"`

	// user name
	// Required: true
	UserName *string `json:"user_name"`
}

// Validate validates this changes change
func (m *ChangesChange) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActionTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateActionType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCid(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCommandLine(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDiff(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEntityPath(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEntityType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFileSize(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHost(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIngestionTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsFromDifferentMountNamespace(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsSuppressed(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissionsLin(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePermissionsMac(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePlatformName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrevalence(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProcessID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProcessImageFileName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ChangesChange) validateActionTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("action_timestamp", "body", m.ActionTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateActionType(formats strfmt.Registry) error {

	if err := validate.Required("action_type", "body", m.ActionType); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateAid(formats strfmt.Registry) error {

	if err := validate.Required("aid", "body", m.Aid); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateAttributes(formats strfmt.Registry) error {
	if swag.IsZero(m.Attributes) { // not required
		return nil
	}

	for i := 0; i < len(m.Attributes); i++ {
		if swag.IsZero(m.Attributes[i]) { // not required
			continue
		}

		if m.Attributes[i] != nil {
			if err := m.Attributes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attributes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("attributes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ChangesChange) validateCid(formats strfmt.Registry) error {

	if err := validate.Required("cid", "body", m.Cid); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateCommandLine(formats strfmt.Registry) error {

	if err := validate.Required("command_line", "body", m.CommandLine); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateDiff(formats strfmt.Registry) error {
	if swag.IsZero(m.Diff) { // not required
		return nil
	}

	if m.Diff != nil {
		if err := m.Diff.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("diff")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("diff")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validateEntityPath(formats strfmt.Registry) error {

	if err := validate.Required("entity_path", "body", m.EntityPath); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateEntityType(formats strfmt.Registry) error {

	if err := validate.Required("entity_type", "body", m.EntityType); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateFileSize(formats strfmt.Registry) error {

	if err := validate.Required("file_size", "body", m.FileSize); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateHost(formats strfmt.Registry) error {
	if swag.IsZero(m.Host) { // not required
		return nil
	}

	if m.Host != nil {
		if err := m.Host.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("host")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("host")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateIngestionTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("ingestion_timestamp", "body", m.IngestionTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateIsFromDifferentMountNamespace(formats strfmt.Registry) error {

	if err := validate.Required("is_from_different_mount_namespace", "body", m.IsFromDifferentMountNamespace); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateIsSuppressed(formats strfmt.Registry) error {

	if err := validate.Required("is_suppressed", "body", m.IsSuppressed); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validatePermissions(formats strfmt.Registry) error {
	if swag.IsZero(m.Permissions) { // not required
		return nil
	}

	if m.Permissions != nil {
		if err := m.Permissions.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validatePermissionsLin(formats strfmt.Registry) error {
	if swag.IsZero(m.PermissionsLin) { // not required
		return nil
	}

	if m.PermissionsLin != nil {
		if err := m.PermissionsLin.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions_lin")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions_lin")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validatePermissionsMac(formats strfmt.Registry) error {
	if swag.IsZero(m.PermissionsMac) { // not required
		return nil
	}

	if m.PermissionsMac != nil {
		if err := m.PermissionsMac.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions_mac")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions_mac")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validatePlatformName(formats strfmt.Registry) error {

	if err := validate.Required("platform_name", "body", m.PlatformName); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validatePolicy(formats strfmt.Registry) error {
	if swag.IsZero(m.Policy) { // not required
		return nil
	}

	if m.Policy != nil {
		if err := m.Policy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validatePrevalence(formats strfmt.Registry) error {
	if swag.IsZero(m.Prevalence) { // not required
		return nil
	}

	if m.Prevalence != nil {
		if err := m.Prevalence.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("prevalence")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("prevalence")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) validateProcessID(formats strfmt.Registry) error {

	if err := validate.Required("process_id", "body", m.ProcessID); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateProcessImageFileName(formats strfmt.Registry) error {

	if err := validate.Required("process_image_file_name", "body", m.ProcessImageFileName); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateSeverity(formats strfmt.Registry) error {

	if err := validate.Required("severity", "body", m.Severity); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateTags(formats strfmt.Registry) error {
	if swag.IsZero(m.Tags) { // not required
		return nil
	}

	for i := 0; i < len(m.Tags); i++ {
		if swag.IsZero(m.Tags[i]) { // not required
			continue
		}

		if m.Tags[i] != nil {
			if err := m.Tags[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("tags" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("tags" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ChangesChange) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("user_id", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

func (m *ChangesChange) validateUserName(formats strfmt.Registry) error {

	if err := validate.Required("user_name", "body", m.UserName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this changes change based on the context it is used
func (m *ChangesChange) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDiff(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateHost(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePermissions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePermissionsLin(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePermissionsMac(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePolicy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePrevalence(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTags(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ChangesChange) contextValidateAttributes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Attributes); i++ {

		if m.Attributes[i] != nil {

			if swag.IsZero(m.Attributes[i]) { // not required
				return nil
			}

			if err := m.Attributes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attributes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("attributes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ChangesChange) contextValidateDiff(ctx context.Context, formats strfmt.Registry) error {

	if m.Diff != nil {

		if swag.IsZero(m.Diff) { // not required
			return nil
		}

		if err := m.Diff.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("diff")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("diff")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidateHost(ctx context.Context, formats strfmt.Registry) error {

	if m.Host != nil {

		if swag.IsZero(m.Host) { // not required
			return nil
		}

		if err := m.Host.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("host")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("host")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidatePermissions(ctx context.Context, formats strfmt.Registry) error {

	if m.Permissions != nil {

		if swag.IsZero(m.Permissions) { // not required
			return nil
		}

		if err := m.Permissions.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidatePermissionsLin(ctx context.Context, formats strfmt.Registry) error {

	if m.PermissionsLin != nil {

		if swag.IsZero(m.PermissionsLin) { // not required
			return nil
		}

		if err := m.PermissionsLin.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions_lin")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions_lin")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidatePermissionsMac(ctx context.Context, formats strfmt.Registry) error {

	if m.PermissionsMac != nil {

		if swag.IsZero(m.PermissionsMac) { // not required
			return nil
		}

		if err := m.PermissionsMac.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("permissions_mac")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("permissions_mac")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidatePolicy(ctx context.Context, formats strfmt.Registry) error {

	if m.Policy != nil {

		if swag.IsZero(m.Policy) { // not required
			return nil
		}

		if err := m.Policy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("policy")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidatePrevalence(ctx context.Context, formats strfmt.Registry) error {

	if m.Prevalence != nil {

		if swag.IsZero(m.Prevalence) { // not required
			return nil
		}

		if err := m.Prevalence.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("prevalence")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("prevalence")
			}
			return err
		}
	}

	return nil
}

func (m *ChangesChange) contextValidateTags(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Tags); i++ {

		if m.Tags[i] != nil {

			if swag.IsZero(m.Tags[i]) { // not required
				return nil
			}

			if err := m.Tags[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("tags" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("tags" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ChangesChange) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ChangesChange) UnmarshalBinary(b []byte) error {
	var res ChangesChange
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
