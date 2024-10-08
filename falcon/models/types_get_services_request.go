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
)

// TypesGetServicesRequest types get services request
//
// swagger:model types.GetServicesRequest
type TypesGetServicesRequest struct {

	// deployment tuple filters
	DeploymentTupleFilters []*TypesDeploymentUnitsTupleFilters `json:"deploymentTupleFilters"`

	// nesting level
	NestingLevel int64 `json:"nestingLevel,omitempty"`

	// only count
	OnlyCount bool `json:"onlyCount,omitempty"`

	// optional time
	OptionalTime int64 `json:"optionalTime,omitempty"`

	// pagination
	Pagination *TypesPagination `json:"pagination,omitempty"`

	// persistent signatures
	PersistentSignatures []string `json:"persistentSignatures"`

	// ql filters
	QlFilters string `json:"qlFilters,omitempty"`

	// related entities
	RelatedEntities []*TypesGetServicesRelatedEntity `json:"relatedEntities"`

	// revision Id
	RevisionID int64 `json:"revisionId,omitempty"`

	// roles signature
	RolesSignature string `json:"rolesSignature,omitempty"`
}

// Validate validates this types get services request
func (m *TypesGetServicesRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDeploymentTupleFilters(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePagination(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRelatedEntities(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesGetServicesRequest) validateDeploymentTupleFilters(formats strfmt.Registry) error {
	if swag.IsZero(m.DeploymentTupleFilters) { // not required
		return nil
	}

	for i := 0; i < len(m.DeploymentTupleFilters); i++ {
		if swag.IsZero(m.DeploymentTupleFilters[i]) { // not required
			continue
		}

		if m.DeploymentTupleFilters[i] != nil {
			if err := m.DeploymentTupleFilters[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("deploymentTupleFilters" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("deploymentTupleFilters" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TypesGetServicesRequest) validatePagination(formats strfmt.Registry) error {
	if swag.IsZero(m.Pagination) { // not required
		return nil
	}

	if m.Pagination != nil {
		if err := m.Pagination.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

func (m *TypesGetServicesRequest) validateRelatedEntities(formats strfmt.Registry) error {
	if swag.IsZero(m.RelatedEntities) { // not required
		return nil
	}

	for i := 0; i < len(m.RelatedEntities); i++ {
		if swag.IsZero(m.RelatedEntities[i]) { // not required
			continue
		}

		if m.RelatedEntities[i] != nil {
			if err := m.RelatedEntities[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("relatedEntities" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("relatedEntities" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this types get services request based on the context it is used
func (m *TypesGetServicesRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDeploymentTupleFilters(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePagination(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRelatedEntities(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TypesGetServicesRequest) contextValidateDeploymentTupleFilters(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DeploymentTupleFilters); i++ {

		if m.DeploymentTupleFilters[i] != nil {

			if swag.IsZero(m.DeploymentTupleFilters[i]) { // not required
				return nil
			}

			if err := m.DeploymentTupleFilters[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("deploymentTupleFilters" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("deploymentTupleFilters" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TypesGetServicesRequest) contextValidatePagination(ctx context.Context, formats strfmt.Registry) error {

	if m.Pagination != nil {

		if swag.IsZero(m.Pagination) { // not required
			return nil
		}

		if err := m.Pagination.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

func (m *TypesGetServicesRequest) contextValidateRelatedEntities(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RelatedEntities); i++ {

		if m.RelatedEntities[i] != nil {

			if swag.IsZero(m.RelatedEntities[i]) { // not required
				return nil
			}

			if err := m.RelatedEntities[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("relatedEntities" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("relatedEntities" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *TypesGetServicesRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TypesGetServicesRequest) UnmarshalBinary(b []byte) error {
	var res TypesGetServicesRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}