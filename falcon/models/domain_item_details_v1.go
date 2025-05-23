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

// DomainItemDetailsV1 domain item details v1
//
// swagger:model domain.ItemDetailsV1
type DomainItemDetailsV1 struct {

	// The threat actor associated with a raw intelligence item, if available.
	ActorSlug string `json:"actor_slug,omitempty"`

	// Attachments items linked to the raw intelligence item
	Attachments []*DomainAttachment `json:"attachments"`

	// The author’s username of a raw intelligence item
	Author string `json:"author,omitempty"`

	// The raw intelligence item author identifier in our system
	AuthorID string `json:"author_id,omitempty"`

	// The type of source where the raw intelligence item was found
	// Required: true
	Category *string `json:"category"`

	// The date and time the raw intelligence item was scraped from the original source
	// Format: date-time
	CollectionDate strfmt.DateTime `json:"collection_date,omitempty"`

	// Highlighted content based on the monitoring rule that generated the notification. Highlights are surrounded with a `<cs-highlight>` tag
	// Required: true
	Content *string `json:"content"`

	// The date and time when the raw intelligence item was created
	// Required: true
	// Format: date-time
	CreatedDate *strfmt.DateTime `json:"created_date"`

	// The file type of the raw intelligence item, if available
	FileType string `json:"file_type,omitempty"`

	// The information available for a fragment item
	FragmentInfo *DomainFragmentInfo `json:"fragment_info,omitempty"`

	// The URL to download the full raw text content of the raw intelligence item. It has a limited time to live
	FullContentURL string `json:"full_content_url,omitempty"`

	// The types of IOCs found in the raw intelligence item. List of keys populated in the iocs field
	IocTypes []string `json:"ioc_types"`

	// Information about IOCs found in a raw intelligence item
	Iocs *DomainIOC `json:"iocs,omitempty"`

	// Labels for the type of information included in a raw intelligence item
	Labels []string `json:"labels"`

	// The language of the raw intelligence item
	Language string `json:"language,omitempty"`

	// Information about marketplace items (cards, hosts, credentials)
	MarketplaceProduct *DomainMarketplaceProduct `json:"marketplace_product,omitempty"`

	// The mime type of the file
	MimeType string `json:"mime_type,omitempty"`

	// Screenshots of the raw intelligence item
	Screenshots []*DomainScreenshot `json:"screenshots"`

	// The SHA256 hash for the file
	Sha256 string `json:"sha256,omitempty"`

	// The site where the raw intelligence item was found
	Site string `json:"site,omitempty"`

	// The ID of the site where the raw intelligence item was found
	// Required: true
	SiteID *string `json:"site_id"`

	// The size of the item's content in bytes, if available
	Size int64 `json:"size,omitempty"`

	// Telegram information
	TelegramInfo *DomainTelegramInfo `json:"telegram_info,omitempty"`

	// Identifier that groups all raw intelligence items belonging to the same conversation thread
	ThreadID string `json:"thread_id,omitempty"`

	// The title of the raw intelligence item
	Title string `json:"title,omitempty"`

	// The type of the raw intelligence item
	// Required: true
	Type *string `json:"type"`

	// The date and time when the raw intelligence item was updated
	// Required: true
	// Format: date-time
	UpdatedDate *strfmt.DateTime `json:"updated_date"`

	// The URL of the raw intelligence item
	URL string `json:"url,omitempty"`

	// The raw intelligence item author identifier in the original source
	UserID string `json:"user_id,omitempty"`
}

// Validate validates this domain item details v1
func (m *DomainItemDetailsV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttachments(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCategory(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCollectionDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFragmentInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIocs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMarketplaceProduct(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScreenshots(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSiteID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTelegramInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainItemDetailsV1) validateAttachments(formats strfmt.Registry) error {
	if swag.IsZero(m.Attachments) { // not required
		return nil
	}

	for i := 0; i < len(m.Attachments); i++ {
		if swag.IsZero(m.Attachments[i]) { // not required
			continue
		}

		if m.Attachments[i] != nil {
			if err := m.Attachments[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attachments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("attachments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainItemDetailsV1) validateCategory(formats strfmt.Registry) error {

	if err := validate.Required("category", "body", m.Category); err != nil {
		return err
	}

	return nil
}

func (m *DomainItemDetailsV1) validateCollectionDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CollectionDate) { // not required
		return nil
	}

	if err := validate.FormatOf("collection_date", "body", "date-time", m.CollectionDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainItemDetailsV1) validateContent(formats strfmt.Registry) error {

	if err := validate.Required("content", "body", m.Content); err != nil {
		return err
	}

	return nil
}

func (m *DomainItemDetailsV1) validateCreatedDate(formats strfmt.Registry) error {

	if err := validate.Required("created_date", "body", m.CreatedDate); err != nil {
		return err
	}

	if err := validate.FormatOf("created_date", "body", "date-time", m.CreatedDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DomainItemDetailsV1) validateFragmentInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.FragmentInfo) { // not required
		return nil
	}

	if m.FragmentInfo != nil {
		if err := m.FragmentInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fragment_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fragment_info")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) validateIocs(formats strfmt.Registry) error {
	if swag.IsZero(m.Iocs) { // not required
		return nil
	}

	if m.Iocs != nil {
		if err := m.Iocs.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("iocs")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("iocs")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) validateMarketplaceProduct(formats strfmt.Registry) error {
	if swag.IsZero(m.MarketplaceProduct) { // not required
		return nil
	}

	if m.MarketplaceProduct != nil {
		if err := m.MarketplaceProduct.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("marketplace_product")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("marketplace_product")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) validateScreenshots(formats strfmt.Registry) error {
	if swag.IsZero(m.Screenshots) { // not required
		return nil
	}

	for i := 0; i < len(m.Screenshots); i++ {
		if swag.IsZero(m.Screenshots[i]) { // not required
			continue
		}

		if m.Screenshots[i] != nil {
			if err := m.Screenshots[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("screenshots" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("screenshots" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainItemDetailsV1) validateSiteID(formats strfmt.Registry) error {

	if err := validate.Required("site_id", "body", m.SiteID); err != nil {
		return err
	}

	return nil
}

func (m *DomainItemDetailsV1) validateTelegramInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.TelegramInfo) { // not required
		return nil
	}

	if m.TelegramInfo != nil {
		if err := m.TelegramInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("telegram_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("telegram_info")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *DomainItemDetailsV1) validateUpdatedDate(formats strfmt.Registry) error {

	if err := validate.Required("updated_date", "body", m.UpdatedDate); err != nil {
		return err
	}

	if err := validate.FormatOf("updated_date", "body", "date-time", m.UpdatedDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain item details v1 based on the context it is used
func (m *DomainItemDetailsV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttachments(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFragmentInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIocs(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMarketplaceProduct(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateScreenshots(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTelegramInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainItemDetailsV1) contextValidateAttachments(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Attachments); i++ {

		if m.Attachments[i] != nil {

			if swag.IsZero(m.Attachments[i]) { // not required
				return nil
			}

			if err := m.Attachments[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attachments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("attachments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainItemDetailsV1) contextValidateFragmentInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.FragmentInfo != nil {

		if swag.IsZero(m.FragmentInfo) { // not required
			return nil
		}

		if err := m.FragmentInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fragment_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fragment_info")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) contextValidateIocs(ctx context.Context, formats strfmt.Registry) error {

	if m.Iocs != nil {

		if swag.IsZero(m.Iocs) { // not required
			return nil
		}

		if err := m.Iocs.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("iocs")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("iocs")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) contextValidateMarketplaceProduct(ctx context.Context, formats strfmt.Registry) error {

	if m.MarketplaceProduct != nil {

		if swag.IsZero(m.MarketplaceProduct) { // not required
			return nil
		}

		if err := m.MarketplaceProduct.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("marketplace_product")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("marketplace_product")
			}
			return err
		}
	}

	return nil
}

func (m *DomainItemDetailsV1) contextValidateScreenshots(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Screenshots); i++ {

		if m.Screenshots[i] != nil {

			if swag.IsZero(m.Screenshots[i]) { // not required
				return nil
			}

			if err := m.Screenshots[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("screenshots" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("screenshots" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainItemDetailsV1) contextValidateTelegramInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.TelegramInfo != nil {

		if swag.IsZero(m.TelegramInfo) { // not required
			return nil
		}

		if err := m.TelegramInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("telegram_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("telegram_info")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainItemDetailsV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainItemDetailsV1) UnmarshalBinary(b []byte) error {
	var res DomainItemDetailsV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
