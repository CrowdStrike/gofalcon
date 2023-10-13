// Code generated by go-swagger; DO NOT EDIT.

package ioc

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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewIndicatorCreateV1Params creates a new IndicatorCreateV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIndicatorCreateV1Params() *IndicatorCreateV1Params {
	return &IndicatorCreateV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewIndicatorCreateV1ParamsWithTimeout creates a new IndicatorCreateV1Params object
// with the ability to set a timeout on a request.
func NewIndicatorCreateV1ParamsWithTimeout(timeout time.Duration) *IndicatorCreateV1Params {
	return &IndicatorCreateV1Params{
		timeout: timeout,
	}
}

// NewIndicatorCreateV1ParamsWithContext creates a new IndicatorCreateV1Params object
// with the ability to set a context for a request.
func NewIndicatorCreateV1ParamsWithContext(ctx context.Context) *IndicatorCreateV1Params {
	return &IndicatorCreateV1Params{
		Context: ctx,
	}
}

// NewIndicatorCreateV1ParamsWithHTTPClient creates a new IndicatorCreateV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewIndicatorCreateV1ParamsWithHTTPClient(client *http.Client) *IndicatorCreateV1Params {
	return &IndicatorCreateV1Params{
		HTTPClient: client,
	}
}

/* IndicatorCreateV1Params contains all the parameters to send to the API endpoint
   for the indicator create v1 operation.

   Typically these are written to a http.Request.
*/
type IndicatorCreateV1Params struct {

	// Body.
	Body *models.APIIndicatorCreateReqsV1

	/* IgnoreWarnings.

	   Set to true to ignore warnings and add all IOCs
	*/
	IgnoreWarnings *bool

	/* Retrodetects.

	   Whether to submit to retrodetects
	*/
	Retrodetects *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the indicator create v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndicatorCreateV1Params) WithDefaults() *IndicatorCreateV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the indicator create v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndicatorCreateV1Params) SetDefaults() {
	var (
		ignoreWarningsDefault = bool(false)
	)

	val := IndicatorCreateV1Params{
		IgnoreWarnings: &ignoreWarningsDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the indicator create v1 params
func (o *IndicatorCreateV1Params) WithTimeout(timeout time.Duration) *IndicatorCreateV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the indicator create v1 params
func (o *IndicatorCreateV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the indicator create v1 params
func (o *IndicatorCreateV1Params) WithContext(ctx context.Context) *IndicatorCreateV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the indicator create v1 params
func (o *IndicatorCreateV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the indicator create v1 params
func (o *IndicatorCreateV1Params) WithHTTPClient(client *http.Client) *IndicatorCreateV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the indicator create v1 params
func (o *IndicatorCreateV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the indicator create v1 params
func (o *IndicatorCreateV1Params) WithBody(body *models.APIIndicatorCreateReqsV1) *IndicatorCreateV1Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the indicator create v1 params
func (o *IndicatorCreateV1Params) SetBody(body *models.APIIndicatorCreateReqsV1) {
	o.Body = body
}

// WithIgnoreWarnings adds the ignoreWarnings to the indicator create v1 params
func (o *IndicatorCreateV1Params) WithIgnoreWarnings(ignoreWarnings *bool) *IndicatorCreateV1Params {
	o.SetIgnoreWarnings(ignoreWarnings)
	return o
}

// SetIgnoreWarnings adds the ignoreWarnings to the indicator create v1 params
func (o *IndicatorCreateV1Params) SetIgnoreWarnings(ignoreWarnings *bool) {
	o.IgnoreWarnings = ignoreWarnings
}

// WithRetrodetects adds the retrodetects to the indicator create v1 params
func (o *IndicatorCreateV1Params) WithRetrodetects(retrodetects *bool) *IndicatorCreateV1Params {
	o.SetRetrodetects(retrodetects)
	return o
}

// SetRetrodetects adds the retrodetects to the indicator create v1 params
func (o *IndicatorCreateV1Params) SetRetrodetects(retrodetects *bool) {
	o.Retrodetects = retrodetects
}

// WriteToRequest writes these params to a swagger request
func (o *IndicatorCreateV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if o.IgnoreWarnings != nil {

		// query param ignore_warnings
		var qrIgnoreWarnings bool

		if o.IgnoreWarnings != nil {
			qrIgnoreWarnings = *o.IgnoreWarnings
		}
		qIgnoreWarnings := swag.FormatBool(qrIgnoreWarnings)
		if qIgnoreWarnings != "" {

			if err := r.SetQueryParam("ignore_warnings", qIgnoreWarnings); err != nil {
				return err
			}
		}
	}

	if o.Retrodetects != nil {

		// query param retrodetects
		var qrRetrodetects bool

		if o.Retrodetects != nil {
			qrRetrodetects = *o.Retrodetects
		}
		qRetrodetects := swag.FormatBool(qrRetrodetects)
		if qRetrodetects != "" {

			if err := r.SetQueryParam("retrodetects", qRetrodetects); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
