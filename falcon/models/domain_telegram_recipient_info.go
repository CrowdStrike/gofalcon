// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomainTelegramRecipientInfo domain telegram recipient info
//
// swagger:model domain.TelegramRecipientInfo
type DomainTelegramRecipientInfo struct {

	// first name
	FirstName string `json:"first_name,omitempty"`

	// id
	ID int64 `json:"id,omitempty"`

	// last name
	LastName string `json:"last_name,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// type
	Type string `json:"type,omitempty"`

	// username
	Username string `json:"username,omitempty"`
}

// Validate validates this domain telegram recipient info
func (m *DomainTelegramRecipientInfo) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this domain telegram recipient info based on context it is used
func (m *DomainTelegramRecipientInfo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainTelegramRecipientInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainTelegramRecipientInfo) UnmarshalBinary(b []byte) error {
	var res DomainTelegramRecipientInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
