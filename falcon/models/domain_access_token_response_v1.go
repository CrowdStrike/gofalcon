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

// DomainAccessTokenResponseV1 domain access token response v1
//
// swagger:model domain.AccessTokenResponseV1
type DomainAccessTokenResponseV1 struct {

	// access token
	// Required: true
	AccessToken *string `json:"access_token"`

	// expires in
	// Required: true
	ExpiresIn *int64 `json:"expires_in"`

	// token type
	// Required: true
	TokenType *string `json:"token_type"`
}

// Validate validates this domain access token response v1
func (m *DomainAccessTokenResponseV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccessToken(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresIn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainAccessTokenResponseV1) validateAccessToken(formats strfmt.Registry) error {

	if err := validate.Required("access_token", "body", m.AccessToken); err != nil {
		return err
	}

	return nil
}

func (m *DomainAccessTokenResponseV1) validateExpiresIn(formats strfmt.Registry) error {

	if err := validate.Required("expires_in", "body", m.ExpiresIn); err != nil {
		return err
	}

	return nil
}

func (m *DomainAccessTokenResponseV1) validateTokenType(formats strfmt.Registry) error {

	if err := validate.Required("token_type", "body", m.TokenType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain access token response v1 based on context it is used
func (m *DomainAccessTokenResponseV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainAccessTokenResponseV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainAccessTokenResponseV1) UnmarshalBinary(b []byte) error {
	var res DomainAccessTokenResponseV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
