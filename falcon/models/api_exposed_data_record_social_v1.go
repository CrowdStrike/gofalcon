// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// APIExposedDataRecordSocialV1 api exposed data record social v1
//
// swagger:model api.ExposedDataRecordSocialV1
type APIExposedDataRecordSocialV1 struct {

	// AIM ID of the affected user
	AimID string `json:"aim_id,omitempty"`

	// Facebook ID of the affected user
	FacebookID string `json:"facebook_id,omitempty"`

	// ICQ ID of the affected user
	IcqID string `json:"icq_id,omitempty"`

	// Instagram ID of the affected user
	InstagramID string `json:"instagram_id,omitempty"`

	// MSN ID of the affected user
	MsnID string `json:"msn_id,omitempty"`

	// Skype ID of the affected user
	SkypeID string `json:"skype_id,omitempty"`

	// Twitter ID of the affected user
	TwitterID string `json:"twitter_id,omitempty"`

	// VK ID of the affected user
	VkID string `json:"vk_id,omitempty"`

	// VK Access Token of the affected user
	VkToken string `json:"vk_token,omitempty"`
}

// Validate validates this api exposed data record social v1
func (m *APIExposedDataRecordSocialV1) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this api exposed data record social v1 based on context it is used
func (m *APIExposedDataRecordSocialV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIExposedDataRecordSocialV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIExposedDataRecordSocialV1) UnmarshalBinary(b []byte) error {
	var res APIExposedDataRecordSocialV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
