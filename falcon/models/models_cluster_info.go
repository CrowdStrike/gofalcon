// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsClusterInfo models cluster info
//
// swagger:model models.ClusterInfo
type ModelsClusterInfo struct {

	// cloud
	Cloud string `json:"cloud,omitempty"`

	// cloud account id
	CloudAccountID string `json:"cloud_account_id,omitempty"`

	// cloud region
	CloudRegion string `json:"cloud_region,omitempty"`

	// cluster id
	ClusterID string `json:"cluster_id,omitempty"`

	// cluster name
	ClusterName string `json:"cluster_name,omitempty"`
}

// Validate validates this models cluster info
func (m *ModelsClusterInfo) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models cluster info based on context it is used
func (m *ModelsClusterInfo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsClusterInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsClusterInfo) UnmarshalBinary(b []byte) error {
	var res ModelsClusterInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}