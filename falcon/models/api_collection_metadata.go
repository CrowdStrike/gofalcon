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

// APICollectionMetadata api collection metadata
//
// swagger:model api.CollectionMetadata
type APICollectionMetadata struct {

	// created by
	CreatedBy *APIUserMetadata `json:"created_by,omitempty"`

	// created timestamp
	// Required: true
	// Format: date-time
	CreatedTimestamp *strfmt.DateTime `json:"created_timestamp"`

	// description
	// Required: true
	Description *string `json:"description"`

	// draft schema version
	DraftSchemaVersion string `json:"draft_schema_version,omitempty"`

	// is global
	// Required: true
	IsGlobal *bool `json:"is_global"`

	// last modified by
	LastModifiedBy *APIUserMetadata `json:"last_modified_by,omitempty"`

	// last modified timestamp
	// Required: true
	// Format: date-time
	LastModifiedTimestamp *strfmt.DateTime `json:"last_modified_timestamp"`

	// name
	// Required: true
	Name *string `json:"name"`

	// namespace
	// Required: true
	Namespace *string `json:"namespace"`

	// permissions
	Permissions []string `json:"permissions"`

	// published version
	PublishedVersion string `json:"published_version,omitempty"`

	// schema version
	// Required: true
	SchemaVersion *string `json:"schema_version"`

	// status
	Status string `json:"status,omitempty"`

	// version
	Version string `json:"version,omitempty"`

	// workflow meta
	WorkflowMeta *APIWorkflowMetadata `json:"workflow_meta,omitempty"`
}

// Validate validates this api collection metadata
func (m *APICollectionMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsGlobal(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastModifiedBy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastModifiedTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNamespace(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchemaVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWorkflowMeta(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APICollectionMetadata) validateCreatedBy(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedBy) { // not required
		return nil
	}

	if m.CreatedBy != nil {
		if err := m.CreatedBy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("created_by")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("created_by")
			}
			return err
		}
	}

	return nil
}

func (m *APICollectionMetadata) validateCreatedTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("created_timestamp", "body", m.CreatedTimestamp); err != nil {
		return err
	}

	if err := validate.FormatOf("created_timestamp", "body", "date-time", m.CreatedTimestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateDescription(formats strfmt.Registry) error {

	if err := validate.Required("description", "body", m.Description); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateIsGlobal(formats strfmt.Registry) error {

	if err := validate.Required("is_global", "body", m.IsGlobal); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateLastModifiedBy(formats strfmt.Registry) error {
	if swag.IsZero(m.LastModifiedBy) { // not required
		return nil
	}

	if m.LastModifiedBy != nil {
		if err := m.LastModifiedBy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("last_modified_by")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("last_modified_by")
			}
			return err
		}
	}

	return nil
}

func (m *APICollectionMetadata) validateLastModifiedTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("last_modified_timestamp", "body", m.LastModifiedTimestamp); err != nil {
		return err
	}

	if err := validate.FormatOf("last_modified_timestamp", "body", "date-time", m.LastModifiedTimestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateNamespace(formats strfmt.Registry) error {

	if err := validate.Required("namespace", "body", m.Namespace); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateSchemaVersion(formats strfmt.Registry) error {

	if err := validate.Required("schema_version", "body", m.SchemaVersion); err != nil {
		return err
	}

	return nil
}

func (m *APICollectionMetadata) validateWorkflowMeta(formats strfmt.Registry) error {
	if swag.IsZero(m.WorkflowMeta) { // not required
		return nil
	}

	if m.WorkflowMeta != nil {
		if err := m.WorkflowMeta.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("workflow_meta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("workflow_meta")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this api collection metadata based on the context it is used
func (m *APICollectionMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreatedBy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLastModifiedBy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWorkflowMeta(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APICollectionMetadata) contextValidateCreatedBy(ctx context.Context, formats strfmt.Registry) error {

	if m.CreatedBy != nil {

		if swag.IsZero(m.CreatedBy) { // not required
			return nil
		}

		if err := m.CreatedBy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("created_by")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("created_by")
			}
			return err
		}
	}

	return nil
}

func (m *APICollectionMetadata) contextValidateLastModifiedBy(ctx context.Context, formats strfmt.Registry) error {

	if m.LastModifiedBy != nil {

		if swag.IsZero(m.LastModifiedBy) { // not required
			return nil
		}

		if err := m.LastModifiedBy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("last_modified_by")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("last_modified_by")
			}
			return err
		}
	}

	return nil
}

func (m *APICollectionMetadata) contextValidateWorkflowMeta(ctx context.Context, formats strfmt.Registry) error {

	if m.WorkflowMeta != nil {

		if swag.IsZero(m.WorkflowMeta) { // not required
			return nil
		}

		if err := m.WorkflowMeta.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("workflow_meta")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("workflow_meta")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *APICollectionMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APICollectionMetadata) UnmarshalBinary(b []byte) error {
	var res APICollectionMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
