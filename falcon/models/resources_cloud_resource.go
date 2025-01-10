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

// ResourcesCloudResource resources cloud resource
//
// swagger:model resources.CloudResource
type ResourcesCloudResource struct {

	// account id
	AccountID string `json:"account_id,omitempty"`

	// account name
	AccountName string `json:"account_name,omitempty"`

	// active
	Active bool `json:"active,omitempty"`

	// arn
	Arn string `json:"arn,omitempty"`

	// category
	Category string `json:"category,omitempty"`

	// cid
	Cid string `json:"cid,omitempty"`

	// cloud context
	CloudContext *ResourcesCloudContext `json:"cloud_context,omitempty"`

	// cloud groups
	CloudGroups []*DomainCloudScope `json:"cloud_groups"`

	// cloud labels
	CloudLabels []*ClassificationLabel `json:"cloud_labels"`

	// cloud provider
	CloudProvider string `json:"cloud_provider,omitempty"`

	// cluster id
	ClusterID string `json:"cluster_id,omitempty"`

	// cluster name
	ClusterName string `json:"cluster_name,omitempty"`

	// configuration
	Configuration ResourcesCloudResourceConfiguration `json:"configuration,omitempty"`

	// creation time
	// Format: date-time
	CreationTime strfmt.DateTime `json:"creation_time,omitempty"`

	// first seen
	// Format: date-time
	FirstSeen strfmt.DateTime `json:"first_seen,omitempty"`

	// hash
	Hash string `json:"hash,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// location
	Location string `json:"location,omitempty"`

	// organization id
	OrganizationID string `json:"organization_id,omitempty"`

	// parent
	Parent string `json:"parent,omitempty"`

	// project id
	ProjectID string `json:"project_id,omitempty"`

	// project number
	ProjectNumber string `json:"project_number,omitempty"`

	// region
	Region string `json:"region,omitempty"`

	// relationships
	Relationships []*ResourcesRelationship `json:"relationships"`

	// resource group
	ResourceGroup string `json:"resource_group,omitempty"`

	// resource id
	ResourceID string `json:"resource_id,omitempty"`

	// resource name
	ResourceName string `json:"resource_name,omitempty"`

	// resource number
	ResourceNumber string `json:"resource_number,omitempty"`

	// resource type
	ResourceType string `json:"resource_type,omitempty"`

	// resource type name
	ResourceTypeName string `json:"resource_type_name,omitempty"`

	// resource url
	ResourceURL string `json:"resource_url,omitempty"`

	// revision
	Revision int32 `json:"revision,omitempty"`

	// service
	Service string `json:"service,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// subscription id
	SubscriptionID string `json:"subscription_id,omitempty"`

	// supplementary configuration
	SupplementaryConfiguration ResourcesCloudResourceSupplementaryConfiguration `json:"supplementary_configuration,omitempty"`

	// tags
	Tags map[string]string `json:"tags,omitempty"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// updated at
	// Format: date-time
	UpdatedAt strfmt.DateTime `json:"updated_at,omitempty"`

	// zone
	Zone string `json:"zone,omitempty"`

	// zones
	Zones []String `json:"zones"`
}

// Validate validates this resources cloud resource
func (m *ResourcesCloudResource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCloudContext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudGroups(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCloudLabels(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreationTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFirstSeen(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRelationships(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResourcesCloudResource) validateCloudContext(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudContext) { // not required
		return nil
	}

	if m.CloudContext != nil {
		if err := m.CloudContext.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cloud_context")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cloud_context")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesCloudResource) validateCloudGroups(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudGroups) { // not required
		return nil
	}

	for i := 0; i < len(m.CloudGroups); i++ {
		if swag.IsZero(m.CloudGroups[i]) { // not required
			continue
		}

		if m.CloudGroups[i] != nil {
			if err := m.CloudGroups[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesCloudResource) validateCloudLabels(formats strfmt.Registry) error {
	if swag.IsZero(m.CloudLabels) { // not required
		return nil
	}

	for i := 0; i < len(m.CloudLabels); i++ {
		if swag.IsZero(m.CloudLabels[i]) { // not required
			continue
		}

		if m.CloudLabels[i] != nil {
			if err := m.CloudLabels[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesCloudResource) validateCreationTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreationTime) { // not required
		return nil
	}

	if err := validate.FormatOf("creation_time", "body", "date-time", m.CreationTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesCloudResource) validateFirstSeen(formats strfmt.Registry) error {
	if swag.IsZero(m.FirstSeen) { // not required
		return nil
	}

	if err := validate.FormatOf("first_seen", "body", "date-time", m.FirstSeen.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ResourcesCloudResource) validateRelationships(formats strfmt.Registry) error {
	if swag.IsZero(m.Relationships) { // not required
		return nil
	}

	for i := 0; i < len(m.Relationships); i++ {
		if swag.IsZero(m.Relationships[i]) { // not required
			continue
		}

		if m.Relationships[i] != nil {
			if err := m.Relationships[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("relationships" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("relationships" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesCloudResource) validateUpdatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("updated_at", "body", "date-time", m.UpdatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this resources cloud resource based on the context it is used
func (m *ResourcesCloudResource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCloudContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCloudGroups(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCloudLabels(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRelationships(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ResourcesCloudResource) contextValidateCloudContext(ctx context.Context, formats strfmt.Registry) error {

	if m.CloudContext != nil {

		if swag.IsZero(m.CloudContext) { // not required
			return nil
		}

		if err := m.CloudContext.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cloud_context")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cloud_context")
			}
			return err
		}
	}

	return nil
}

func (m *ResourcesCloudResource) contextValidateCloudGroups(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CloudGroups); i++ {

		if m.CloudGroups[i] != nil {

			if swag.IsZero(m.CloudGroups[i]) { // not required
				return nil
			}

			if err := m.CloudGroups[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_groups" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesCloudResource) contextValidateCloudLabels(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CloudLabels); i++ {

		if m.CloudLabels[i] != nil {

			if swag.IsZero(m.CloudLabels[i]) { // not required
				return nil
			}

			if err := m.CloudLabels[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("cloud_labels" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ResourcesCloudResource) contextValidateRelationships(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Relationships); i++ {

		if m.Relationships[i] != nil {

			if swag.IsZero(m.Relationships[i]) { // not required
				return nil
			}

			if err := m.Relationships[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("relationships" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("relationships" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ResourcesCloudResource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResourcesCloudResource) UnmarshalBinary(b []byte) error {
	var res ResourcesCloudResource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
