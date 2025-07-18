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

// DomainSimpleActor domain simple actor
//
// swagger:model domain.SimpleActor
type DomainSimpleActor struct {

	// animal classifier
	AnimalClassifier string `json:"animal_classifier,omitempty"`

	// entitlements
	Entitlements []*DomainEntity `json:"entitlements"`

	// id
	// Required: true
	ID *int64 `json:"id"`

	// name
	Name string `json:"name,omitempty"`

	// slug
	Slug string `json:"slug,omitempty"`

	// thumbnail
	Thumbnail *DomainImage `json:"thumbnail,omitempty"`

	// url
	URL string `json:"url,omitempty"`
}

// Validate validates this domain simple actor
func (m *DomainSimpleActor) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEntitlements(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateThumbnail(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainSimpleActor) validateEntitlements(formats strfmt.Registry) error {
	if swag.IsZero(m.Entitlements) { // not required
		return nil
	}

	for i := 0; i < len(m.Entitlements); i++ {
		if swag.IsZero(m.Entitlements[i]) { // not required
			continue
		}

		if m.Entitlements[i] != nil {
			if err := m.Entitlements[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("entitlements" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("entitlements" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainSimpleActor) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainSimpleActor) validateThumbnail(formats strfmt.Registry) error {
	if swag.IsZero(m.Thumbnail) { // not required
		return nil
	}

	if m.Thumbnail != nil {
		if err := m.Thumbnail.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("thumbnail")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("thumbnail")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domain simple actor based on the context it is used
func (m *DomainSimpleActor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEntitlements(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThumbnail(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainSimpleActor) contextValidateEntitlements(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Entitlements); i++ {

		if m.Entitlements[i] != nil {

			if swag.IsZero(m.Entitlements[i]) { // not required
				return nil
			}

			if err := m.Entitlements[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("entitlements" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("entitlements" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainSimpleActor) contextValidateThumbnail(ctx context.Context, formats strfmt.Registry) error {

	if m.Thumbnail != nil {

		if swag.IsZero(m.Thumbnail) { // not required
			return nil
		}

		if err := m.Thumbnail.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("thumbnail")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("thumbnail")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainSimpleActor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainSimpleActor) UnmarshalBinary(b []byte) error {
	var res DomainSimpleActor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
