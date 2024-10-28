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

// NewGetIntegrationTasksParams creates a new GetIntegrationTasksParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetIntegrationTasksParams() *GetIntegrationTasksParams {
	return &GetIntegrationTasksParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetIntegrationTasksParamsWithTimeout creates a new GetIntegrationTasksParams object
// with the ability to set a timeout on a request.
func NewGetIntegrationTasksParamsWithTimeout(timeout time.Duration) *GetIntegrationTasksParams {
	return &GetIntegrationTasksParams{
		timeout: timeout,
	}
}

// NewGetIntegrationTasksParamsWithContext creates a new GetIntegrationTasksParams object
// with the ability to set a context for a request.
func NewGetIntegrationTasksParamsWithContext(ctx context.Context) *GetIntegrationTasksParams {
	return &GetIntegrationTasksParams{
		Context: ctx,
	}
}

// NewGetIntegrationTasksParamsWithHTTPClient creates a new GetIntegrationTasksParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetIntegrationTasksParamsWithHTTPClient(client *http.Client) *GetIntegrationTasksParams {
	return &GetIntegrationTasksParams{
		HTTPClient: client,
	}
}

/*
GetIntegrationTasksParams contains all the parameters to send to the API endpoint

	for the get integration tasks operation.

	Typically these are written to a http.Request.
*/
type GetIntegrationTasksParams struct {

	// Category.
	Category *string

	// IntegrationTaskType.
	IntegrationTaskType *int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get integration tasks params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetIntegrationTasksParams) WithDefaults() *GetIntegrationTasksParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get integration tasks params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetIntegrationTasksParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get integration tasks params
func (o *GetIntegrationTasksParams) WithTimeout(timeout time.Duration) *GetIntegrationTasksParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get integration tasks params
func (o *GetIntegrationTasksParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get integration tasks params
func (o *GetIntegrationTasksParams) WithContext(ctx context.Context) *GetIntegrationTasksParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get integration tasks params
func (o *GetIntegrationTasksParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get integration tasks params
func (o *GetIntegrationTasksParams) WithHTTPClient(client *http.Client) *GetIntegrationTasksParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get integration tasks params
func (o *GetIntegrationTasksParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCategory adds the category to the get integration tasks params
func (o *GetIntegrationTasksParams) WithCategory(category *string) *GetIntegrationTasksParams {
	o.SetCategory(category)
	return o
}

// SetCategory adds the category to the get integration tasks params
func (o *GetIntegrationTasksParams) SetCategory(category *string) {
	o.Category = category
}

// WithIntegrationTaskType adds the integrationTaskType to the get integration tasks params
func (o *GetIntegrationTasksParams) WithIntegrationTaskType(integrationTaskType *int64) *GetIntegrationTasksParams {
	o.SetIntegrationTaskType(integrationTaskType)
	return o
}

// SetIntegrationTaskType adds the integrationTaskType to the get integration tasks params
func (o *GetIntegrationTasksParams) SetIntegrationTaskType(integrationTaskType *int64) {
	o.IntegrationTaskType = integrationTaskType
}

// WriteToRequest writes these params to a swagger request
func (o *GetIntegrationTasksParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
