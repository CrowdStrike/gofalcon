// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomainMarketplaceCredentials domain marketplace credentials
//
// swagger:model domain.MarketplaceCredentials
type DomainMarketplaceCredentials struct {

	// sites all
	SitesAll []string `json:"sites_all"`

	// sites with cookie only
	SitesWithCookieOnly []string `json:"sites_with_cookie_only"`

	// sites with password
	SitesWithPassword []string `json:"sites_with_password"`
}

// Validate validates this domain marketplace credentials
func (m *DomainMarketplaceCredentials) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this domain marketplace credentials based on context it is used
func (m *DomainMarketplaceCredentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainMarketplaceCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainMarketplaceCredentials) UnmarshalBinary(b []byte) error {
	var res DomainMarketplaceCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
