// Code generated by go-swagger; DO NOT EDIT.

package alerts

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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewPostAggregatesAlertsV1Params creates a new PostAggregatesAlertsV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostAggregatesAlertsV1Params() *PostAggregatesAlertsV1Params {
	return &PostAggregatesAlertsV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostAggregatesAlertsV1ParamsWithTimeout creates a new PostAggregatesAlertsV1Params object
// with the ability to set a timeout on a request.
func NewPostAggregatesAlertsV1ParamsWithTimeout(timeout time.Duration) *PostAggregatesAlertsV1Params {
	return &PostAggregatesAlertsV1Params{
		timeout: timeout,
	}
}

// NewPostAggregatesAlertsV1ParamsWithContext creates a new PostAggregatesAlertsV1Params object
// with the ability to set a context for a request.
func NewPostAggregatesAlertsV1ParamsWithContext(ctx context.Context) *PostAggregatesAlertsV1Params {
	return &PostAggregatesAlertsV1Params{
		Context: ctx,
	}
}

// NewPostAggregatesAlertsV1ParamsWithHTTPClient creates a new PostAggregatesAlertsV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewPostAggregatesAlertsV1ParamsWithHTTPClient(client *http.Client) *PostAggregatesAlertsV1Params {
	return &PostAggregatesAlertsV1Params{
		HTTPClient: client,
	}
}

/* PostAggregatesAlertsV1Params contains all the parameters to send to the API endpoint
   for the post aggregates alerts v1 operation.

   Typically these are written to a http.Request.
*/
type PostAggregatesAlertsV1Params struct {

	/* Body.

	   request body takes a list of aggregate-alert query requests
	*/
	Body []*models.DetectsapiAggregateAlertQueryRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post aggregates alerts v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAggregatesAlertsV1Params) WithDefaults() *PostAggregatesAlertsV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post aggregates alerts v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAggregatesAlertsV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) WithTimeout(timeout time.Duration) *PostAggregatesAlertsV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) WithContext(ctx context.Context) *PostAggregatesAlertsV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) WithHTTPClient(client *http.Client) *PostAggregatesAlertsV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) WithBody(body []*models.DetectsapiAggregateAlertQueryRequest) *PostAggregatesAlertsV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the post aggregates alerts v1 params
func (o *PostAggregatesAlertsV1Params) SetBody(body []*models.DetectsapiAggregateAlertQueryRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PostAggregatesAlertsV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
