// Code generated by go-swagger; DO NOT EDIT.

package user_management

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

// NewRetrieveUsersGETV1Params creates a new RetrieveUsersGETV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRetrieveUsersGETV1Params() *RetrieveUsersGETV1Params {
	return &RetrieveUsersGETV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewRetrieveUsersGETV1ParamsWithTimeout creates a new RetrieveUsersGETV1Params object
// with the ability to set a timeout on a request.
func NewRetrieveUsersGETV1ParamsWithTimeout(timeout time.Duration) *RetrieveUsersGETV1Params {
	return &RetrieveUsersGETV1Params{
		timeout: timeout,
	}
}

// NewRetrieveUsersGETV1ParamsWithContext creates a new RetrieveUsersGETV1Params object
// with the ability to set a context for a request.
func NewRetrieveUsersGETV1ParamsWithContext(ctx context.Context) *RetrieveUsersGETV1Params {
	return &RetrieveUsersGETV1Params{
		Context: ctx,
	}
}

// NewRetrieveUsersGETV1ParamsWithHTTPClient creates a new RetrieveUsersGETV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewRetrieveUsersGETV1ParamsWithHTTPClient(client *http.Client) *RetrieveUsersGETV1Params {
	return &RetrieveUsersGETV1Params{
		HTTPClient: client,
	}
}

/* RetrieveUsersGETV1Params contains all the parameters to send to the API endpoint
   for the retrieve users g e t v1 operation.

   Typically these are written to a http.Request.
*/
type RetrieveUsersGETV1Params struct {

	/* Body.

	   Maximum of 5000 User UUIDs can be specified per request.
	*/
	Body *models.MsaspecIdsRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the retrieve users g e t v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RetrieveUsersGETV1Params) WithDefaults() *RetrieveUsersGETV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the retrieve users g e t v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RetrieveUsersGETV1Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) WithTimeout(timeout time.Duration) *RetrieveUsersGETV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) WithContext(ctx context.Context) *RetrieveUsersGETV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) WithHTTPClient(client *http.Client) *RetrieveUsersGETV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) WithBody(body *models.MsaspecIdsRequest) *RetrieveUsersGETV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the retrieve users g e t v1 params
func (o *RetrieveUsersGETV1Params) SetBody(body *models.MsaspecIdsRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *RetrieveUsersGETV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
