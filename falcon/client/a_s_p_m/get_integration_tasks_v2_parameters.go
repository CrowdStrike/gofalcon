// Code generated by go-swagger; DO NOT EDIT.

package a_s_p_m

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetIntegrationTasksV2Params creates a new GetIntegrationTasksV2Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetIntegrationTasksV2Params() *GetIntegrationTasksV2Params {
	return &GetIntegrationTasksV2Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetIntegrationTasksV2ParamsWithTimeout creates a new GetIntegrationTasksV2Params object
// with the ability to set a timeout on a request.
func NewGetIntegrationTasksV2ParamsWithTimeout(timeout time.Duration) *GetIntegrationTasksV2Params {
	return &GetIntegrationTasksV2Params{
		timeout: timeout,
	}
}

// NewGetIntegrationTasksV2ParamsWithContext creates a new GetIntegrationTasksV2Params object
// with the ability to set a context for a request.
func NewGetIntegrationTasksV2ParamsWithContext(ctx context.Context) *GetIntegrationTasksV2Params {
	return &GetIntegrationTasksV2Params{
		Context: ctx,
	}
}

// NewGetIntegrationTasksV2ParamsWithHTTPClient creates a new GetIntegrationTasksV2Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetIntegrationTasksV2ParamsWithHTTPClient(client *http.Client) *GetIntegrationTasksV2Params {
	return &GetIntegrationTasksV2Params{
		HTTPClient: client,
	}
}

/*
GetIntegrationTasksV2Params contains all the parameters to send to the API endpoint

	for the get integration tasks v2 operation.

	Typically these are written to a http.Request.
*/
type GetIntegrationTasksV2Params struct {

	// Category.
	Category *string

	// Direction.
	Direction *string

	// Ids.
	Ids *int64

	// IntegrationTaskType.
	IntegrationTaskType *int64

	// IntegrationTaskTypes.
	IntegrationTaskTypes *int64

	// Limit.
	Limit *int64

	// Names.
	Names *string

	// Offset.
	Offset *int64

	// OrderBy.
	OrderBy *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get integration tasks v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetIntegrationTasksV2Params) WithDefaults() *GetIntegrationTasksV2Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get integration tasks v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetIntegrationTasksV2Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithTimeout(timeout time.Duration) *GetIntegrationTasksV2Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithContext(ctx context.Context) *GetIntegrationTasksV2Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithHTTPClient(client *http.Client) *GetIntegrationTasksV2Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCategory adds the category to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithCategory(category *string) *GetIntegrationTasksV2Params {
	o.SetCategory(category)
	return o
}

// SetCategory adds the category to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetCategory(category *string) {
	o.Category = category
}

// WithDirection adds the direction to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithDirection(direction *string) *GetIntegrationTasksV2Params {
	o.SetDirection(direction)
	return o
}

// SetDirection adds the direction to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetDirection(direction *string) {
	o.Direction = direction
}

// WithIds adds the ids to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithIds(ids *int64) *GetIntegrationTasksV2Params {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetIds(ids *int64) {
	o.Ids = ids
}

// WithIntegrationTaskType adds the integrationTaskType to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithIntegrationTaskType(integrationTaskType *int64) *GetIntegrationTasksV2Params {
	o.SetIntegrationTaskType(integrationTaskType)
	return o
}

// SetIntegrationTaskType adds the integrationTaskType to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetIntegrationTaskType(integrationTaskType *int64) {
	o.IntegrationTaskType = integrationTaskType
}

// WithIntegrationTaskTypes adds the integrationTaskTypes to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithIntegrationTaskTypes(integrationTaskTypes *int64) *GetIntegrationTasksV2Params {
	o.SetIntegrationTaskTypes(integrationTaskTypes)
	return o
}

// SetIntegrationTaskTypes adds the integrationTaskTypes to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetIntegrationTaskTypes(integrationTaskTypes *int64) {
	o.IntegrationTaskTypes = integrationTaskTypes
}

// WithLimit adds the limit to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithLimit(limit *int64) *GetIntegrationTasksV2Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithNames adds the names to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithNames(names *string) *GetIntegrationTasksV2Params {
	o.SetNames(names)
	return o
}

// SetNames adds the names to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetNames(names *string) {
	o.Names = names
}

// WithOffset adds the offset to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithOffset(offset *int64) *GetIntegrationTasksV2Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithOrderBy adds the orderBy to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) WithOrderBy(orderBy *string) *GetIntegrationTasksV2Params {
	o.SetOrderBy(orderBy)
	return o
}

// SetOrderBy adds the orderBy to the get integration tasks v2 params
func (o *GetIntegrationTasksV2Params) SetOrderBy(orderBy *string) {
	o.OrderBy = orderBy
}

// WriteToRequest writes these params to a swagger request
func (o *GetIntegrationTasksV2Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Category != nil {

		// query param category
		var qrCategory string

		if o.Category != nil {
			qrCategory = *o.Category
		}
		qCategory := qrCategory
		if qCategory != "" {

			if err := r.SetQueryParam("category", qCategory); err != nil {
				return err
			}
		}
	}

	if o.Direction != nil {

		// query param direction
		var qrDirection string

		if o.Direction != nil {
			qrDirection = *o.Direction
		}
		qDirection := qrDirection
		if qDirection != "" {

			if err := r.SetQueryParam("direction", qDirection); err != nil {
				return err
			}
		}
	}

	if o.Ids != nil {

		// query param ids
		var qrIds int64

		if o.Ids != nil {
			qrIds = *o.Ids
		}
		qIds := swag.FormatInt64(qrIds)
		if qIds != "" {

			if err := r.SetQueryParam("ids", qIds); err != nil {
				return err
			}
		}
	}

	if o.IntegrationTaskType != nil {

		// query param integration_task_type
		var qrIntegrationTaskType int64

		if o.IntegrationTaskType != nil {
			qrIntegrationTaskType = *o.IntegrationTaskType
		}
		qIntegrationTaskType := swag.FormatInt64(qrIntegrationTaskType)
		if qIntegrationTaskType != "" {

			if err := r.SetQueryParam("integration_task_type", qIntegrationTaskType); err != nil {
				return err
			}
		}
	}

	if o.IntegrationTaskTypes != nil {

		// query param integration_task_types
		var qrIntegrationTaskTypes int64

		if o.IntegrationTaskTypes != nil {
			qrIntegrationTaskTypes = *o.IntegrationTaskTypes
		}
		qIntegrationTaskTypes := swag.FormatInt64(qrIntegrationTaskTypes)
		if qIntegrationTaskTypes != "" {

			if err := r.SetQueryParam("integration_task_types", qIntegrationTaskTypes); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Names != nil {

		// query param names
		var qrNames string

		if o.Names != nil {
			qrNames = *o.Names
		}
		qNames := qrNames
		if qNames != "" {

			if err := r.SetQueryParam("names", qNames); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int64

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt64(qrOffset)
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if o.OrderBy != nil {

		// query param orderBy
		var qrOrderBy string

		if o.OrderBy != nil {
			qrOrderBy = *o.OrderBy
		}
		qOrderBy := qrOrderBy
		if qOrderBy != "" {

			if err := r.SetQueryParam("orderBy", qOrderBy); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
