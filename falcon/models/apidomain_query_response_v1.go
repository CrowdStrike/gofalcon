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

// ApidomainQueryResponseV1 apidomain query response v1
//
// swagger:model apidomain.QueryResponseV1
type ApidomainQueryResponseV1 struct {

	// event count
	// Required: true
	EventCount *int32 `json:"event_count"`

	// events
	// Required: true
	Events []ApidomainQueryResponseV1Events `json:"events"`

	// fields
	Fields []*ClientField `json:"fields"`

	// filtered event count
	// Required: true
	FilteredEventCount *int32 `json:"filtered_event_count"`

	// job status
	JobStatus *ClientJobStatus `json:"job_status,omitempty"`

	// meta data
	MetaData *ClientQueryResultMetadata `json:"meta_data,omitempty"`

	// schemas
	Schemas *ClientQueryResponseSchemasV1 `json:"schemas,omitempty"`
}

// Validate validates this apidomain query response v1
func (m *ApidomainQueryResponseV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEventCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEvents(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFields(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFilteredEventCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJobStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetaData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchemas(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ApidomainQueryResponseV1) validateEventCount(formats strfmt.Registry) error {

	if err := validate.Required("event_count", "body", m.EventCount); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainQueryResponseV1) validateEvents(formats strfmt.Registry) error {

	if err := validate.Required("events", "body", m.Events); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainQueryResponseV1) validateFields(formats strfmt.Registry) error {
	if swag.IsZero(m.Fields) { // not required
		return nil
	}

	for i := 0; i < len(m.Fields); i++ {
		if swag.IsZero(m.Fields[i]) { // not required
			continue
		}

		if m.Fields[i] != nil {
			if err := m.Fields[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("fields" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("fields" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ApidomainQueryResponseV1) validateFilteredEventCount(formats strfmt.Registry) error {

	if err := validate.Required("filtered_event_count", "body", m.FilteredEventCount); err != nil {
		return err
	}

	return nil
}

func (m *ApidomainQueryResponseV1) validateJobStatus(formats strfmt.Registry) error {
	if swag.IsZero(m.JobStatus) { // not required
		return nil
	}

	if m.JobStatus != nil {
		if err := m.JobStatus.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("job_status")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("job_status")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainQueryResponseV1) validateMetaData(formats strfmt.Registry) error {
	if swag.IsZero(m.MetaData) { // not required
		return nil
	}

	if m.MetaData != nil {
		if err := m.MetaData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("meta_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("meta_data")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainQueryResponseV1) validateSchemas(formats strfmt.Registry) error {
	if swag.IsZero(m.Schemas) { // not required
		return nil
	}

	if m.Schemas != nil {
		if err := m.Schemas.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("schemas")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("schemas")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this apidomain query response v1 based on the context it is used
func (m *ApidomainQueryResponseV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFields(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJobStatus(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMetaData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSchemas(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ApidomainQueryResponseV1) contextValidateFields(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Fields); i++ {

		if m.Fields[i] != nil {

			if swag.IsZero(m.Fields[i]) { // not required
				return nil
			}

			if err := m.Fields[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("fields" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("fields" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ApidomainQueryResponseV1) contextValidateJobStatus(ctx context.Context, formats strfmt.Registry) error {

	if m.JobStatus != nil {

		if swag.IsZero(m.JobStatus) { // not required
			return nil
		}

		if err := m.JobStatus.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("job_status")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("job_status")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainQueryResponseV1) contextValidateMetaData(ctx context.Context, formats strfmt.Registry) error {

	if m.MetaData != nil {

		if swag.IsZero(m.MetaData) { // not required
			return nil
		}

		if err := m.MetaData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("meta_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("meta_data")
			}
			return err
		}
	}

	return nil
}

func (m *ApidomainQueryResponseV1) contextValidateSchemas(ctx context.Context, formats strfmt.Registry) error {

	if m.Schemas != nil {

		if swag.IsZero(m.Schemas) { // not required
			return nil
		}

		if err := m.Schemas.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("schemas")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("schemas")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ApidomainQueryResponseV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ApidomainQueryResponseV1) UnmarshalBinary(b []byte) error {
	var res ApidomainQueryResponseV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
