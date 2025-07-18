// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5 data transaction response dto 85fe65bca8c74e8abd9744f1accd57e5
//
// swagger:model DataTransactionResponseDto_85fe65bca8c74e8abd9744f1accd57e5
type DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5 struct {

	// Account id
	// Required: true
	// Min Length: 1
	AccountID *string `json:"account_id"`

	// Account integration id
	// Required: true
	// Min Length: 1
	AccountIntegrationID *string `json:"account_integration_id"`

	// Last update
	// Required: true
	// Format: date-time
	LastUpdate *strfmt.DateTime `json:"last_update"`

	// sources
	// Required: true
	Sources []*Source187c0280ad3e4902becd3170cc483b36 `json:"sources"`

	// Status
	// Required: true
	// Enum: [cancelled closed done in_progress pending]
	Status *string `json:"status"`
}

// Validate validates this data transaction response dto 85fe65bca8c74e8abd9744f1accd57e5
func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAccountIntegrationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastUpdate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSources(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) validateAccountID(formats strfmt.Registry) error {

	if err := validate.Required("account_id", "body", m.AccountID); err != nil {
		return err
	}

	if err := validate.MinLength("account_id", "body", *m.AccountID, 1); err != nil {
		return err
	}

	return nil
}

func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) validateAccountIntegrationID(formats strfmt.Registry) error {

	if err := validate.Required("account_integration_id", "body", m.AccountIntegrationID); err != nil {
		return err
	}

	if err := validate.MinLength("account_integration_id", "body", *m.AccountIntegrationID, 1); err != nil {
		return err
	}

	return nil
}

func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) validateLastUpdate(formats strfmt.Registry) error {

	if err := validate.Required("last_update", "body", m.LastUpdate); err != nil {
		return err
	}

	if err := validate.FormatOf("last_update", "body", "date-time", m.LastUpdate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) validateSources(formats strfmt.Registry) error {

	if err := validate.Required("sources", "body", m.Sources); err != nil {
		return err
	}

	for i := 0; i < len(m.Sources); i++ {
		if swag.IsZero(m.Sources[i]) { // not required
			continue
		}

		if m.Sources[i] != nil {
			if err := m.Sources[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("sources" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("sources" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var dataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5TypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["cancelled","closed","done","in_progress","pending"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		dataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5TypeStatusPropEnum = append(dataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5TypeStatusPropEnum, v)
	}
}

const (

	// DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusCancelled captures enum value "cancelled"
	DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusCancelled string = "cancelled"

	// DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusClosed captures enum value "closed"
	DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusClosed string = "closed"

	// DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusDone captures enum value "done"
	DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusDone string = "done"

	// DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusInProgress captures enum value "in_progress"
	DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusInProgress string = "in_progress"

	// DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusPending captures enum value "pending"
	DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5StatusPending string = "pending"
)

// prop value enum
func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, dataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5TypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", *m.Status); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this data transaction response dto 85fe65bca8c74e8abd9744f1accd57e5 based on the context it is used
func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSources(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) contextValidateSources(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Sources); i++ {

		if m.Sources[i] != nil {

			if swag.IsZero(m.Sources[i]) { // not required
				return nil
			}

			if err := m.Sources[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("sources" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("sources" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5) UnmarshalBinary(b []byte) error {
	var res DataTransactionResponseDto85fe65bca8c74e8abd9744f1accd57e5
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
