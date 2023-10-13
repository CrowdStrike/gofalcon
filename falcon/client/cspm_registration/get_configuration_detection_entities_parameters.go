// Code generated by go-swagger; DO NOT EDIT.

package cspm_registration

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

// NewGetConfigurationDetectionEntitiesParams creates a new GetConfigurationDetectionEntitiesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetConfigurationDetectionEntitiesParams() *GetConfigurationDetectionEntitiesParams {
	return &GetConfigurationDetectionEntitiesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetConfigurationDetectionEntitiesParamsWithTimeout creates a new GetConfigurationDetectionEntitiesParams object
// with the ability to set a timeout on a request.
func NewGetConfigurationDetectionEntitiesParamsWithTimeout(timeout time.Duration) *GetConfigurationDetectionEntitiesParams {
	return &GetConfigurationDetectionEntitiesParams{
		timeout: timeout,
	}
}

// NewGetConfigurationDetectionEntitiesParamsWithContext creates a new GetConfigurationDetectionEntitiesParams object
// with the ability to set a context for a request.
func NewGetConfigurationDetectionEntitiesParamsWithContext(ctx context.Context) *GetConfigurationDetectionEntitiesParams {
	return &GetConfigurationDetectionEntitiesParams{
		Context: ctx,
	}
}

// NewGetConfigurationDetectionEntitiesParamsWithHTTPClient creates a new GetConfigurationDetectionEntitiesParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetConfigurationDetectionEntitiesParamsWithHTTPClient(client *http.Client) *GetConfigurationDetectionEntitiesParams {
	return &GetConfigurationDetectionEntitiesParams{
		HTTPClient: client,
	}
}

/* GetConfigurationDetectionEntitiesParams contains all the parameters to send to the API endpoint
   for the get configuration detection entities operation.

   Typically these are written to a http.Request.
*/
type GetConfigurationDetectionEntitiesParams struct {

	/* Ids.

	   detection ids
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get configuration detection entities params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetConfigurationDetectionEntitiesParams) WithDefaults() *GetConfigurationDetectionEntitiesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get configuration detection entities params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetConfigurationDetectionEntitiesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) WithTimeout(timeout time.Duration) *GetConfigurationDetectionEntitiesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) WithContext(ctx context.Context) *GetConfigurationDetectionEntitiesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) WithHTTPClient(client *http.Client) *GetConfigurationDetectionEntitiesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) WithIds(ids []string) *GetConfigurationDetectionEntitiesParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get configuration detection entities params
func (o *GetConfigurationDetectionEntitiesParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetConfigurationDetectionEntitiesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Ids != nil {

		// binding items for ids
		joinedIds := o.bindParamIds(reg)

		// query array param ids
		if err := r.SetQueryParam("ids", joinedIds...); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamGetConfigurationDetectionEntities binds the parameter ids
func (o *GetConfigurationDetectionEntitiesParams) bindParamIds(formats strfmt.Registry) []string {
	idsIR := o.Ids

	var idsIC []string
	for _, idsIIR := range idsIR { // explode []string

		idsIIV := idsIIR // string as string
		idsIC = append(idsIC, idsIIV)
	}

	// items.CollectionFormat: "multi"
	idsIS := swag.JoinByFormat(idsIC, "multi")

	return idsIS
}
