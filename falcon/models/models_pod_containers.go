// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// ModelsPodContainers models pod containers
//
// swagger:model models.Pod.containers
type ModelsPodContainers map[string]string

// Validate validates this models pod containers
func (m ModelsPodContainers) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models pod containers based on context it is used
func (m ModelsPodContainers) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
