// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ResourcesAssetGraph resources asset graph
//
// swagger:model resources.AssetGraph
type ResourcesAssetGraph struct {

	// id
	ID string `json:"id,omitempty"`

	// res id
	ResID string `json:"res_id,omitempty"`
}

// Validate validates this resources asset graph
func (m *ResourcesAssetGraph) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this resources asset graph based on context it is used
func (m *ResourcesAssetGraph) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ResourcesAssetGraph) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ResourcesAssetGraph) UnmarshalBinary(b []byte) error {
	var res ResourcesAssetGraph
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
