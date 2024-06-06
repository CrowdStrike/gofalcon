// Code generated by go-swagger; DO NOT EDIT.

package malquery

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

	"github.com/aslape/gofalcon/falcon/models"
)

// NewPostMalQueryHuntV1Params creates a new PostMalQueryHuntV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostMalQueryHuntV1Params() *PostMalQueryHuntV1Params {
	return &PostMalQueryHuntV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostMalQueryHuntV1ParamsWithTimeout creates a new PostMalQueryHuntV1Params object
// with the ability to set a timeout on a request.
func NewPostMalQueryHuntV1ParamsWithTimeout(timeout time.Duration) *PostMalQueryHuntV1Params {
	return &PostMalQueryHuntV1Params{
		timeout: timeout,
	}
}

// NewPostMalQueryHuntV1ParamsWithContext creates a new PostMalQueryHuntV1Params object
// with the ability to set a context for a request.
func NewPostMalQueryHuntV1ParamsWithContext(ctx context.Context) *PostMalQueryHuntV1Params {
	return &PostMalQueryHuntV1Params{
		Context: ctx,
	}
}

// NewPostMalQueryHuntV1ParamsWithHTTPClient creates a new PostMalQueryHuntV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewPostMalQueryHuntV1ParamsWithHTTPClient(client *http.Client) *PostMalQueryHuntV1Params {
	return &PostMalQueryHuntV1Params{
		HTTPClient: client,
	}
}

/*
PostMalQueryHuntV1Params contains all the parameters to send to the API endpoint

	for the post mal query hunt v1 operation.

	Typically these are written to a http.Request.
*/
type PostMalQueryHuntV1Params struct {

	/* Body.

	   Hunt parameters. See model for more details.
	*/
	Body *models.MalqueryExternalHuntParametersV1

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post mal query hunt v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostMalQueryHuntV1Params) WithDefaults() *PostMalQueryHuntV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post mal query hunt v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostMalQueryHuntV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) WithTimeout(timeout time.Duration) *PostMalQueryHuntV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) WithContext(ctx context.Context) *PostMalQueryHuntV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) WithHTTPClient(client *http.Client) *PostMalQueryHuntV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) WithBody(body *models.MalqueryExternalHuntParametersV1) *PostMalQueryHuntV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the post mal query hunt v1 params
func (o *PostMalQueryHuntV1Params) SetBody(body *models.MalqueryExternalHuntParametersV1) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PostMalQueryHuntV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
