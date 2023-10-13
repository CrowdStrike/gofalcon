// Code generated by go-swagger; DO NOT EDIT.

package falconx_sandbox

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
)

// NewGetArtifactsParams creates a new GetArtifactsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetArtifactsParams() *GetArtifactsParams {
	return &GetArtifactsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetArtifactsParamsWithTimeout creates a new GetArtifactsParams object
// with the ability to set a timeout on a request.
func NewGetArtifactsParamsWithTimeout(timeout time.Duration) *GetArtifactsParams {
	return &GetArtifactsParams{
		timeout: timeout,
	}
}

// NewGetArtifactsParamsWithContext creates a new GetArtifactsParams object
// with the ability to set a context for a request.
func NewGetArtifactsParamsWithContext(ctx context.Context) *GetArtifactsParams {
	return &GetArtifactsParams{
		Context: ctx,
	}
}

// NewGetArtifactsParamsWithHTTPClient creates a new GetArtifactsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetArtifactsParamsWithHTTPClient(client *http.Client) *GetArtifactsParams {
	return &GetArtifactsParams{
		HTTPClient: client,
	}
}

/* GetArtifactsParams contains all the parameters to send to the API endpoint
   for the get artifacts operation.

   Typically these are written to a http.Request.
*/
type GetArtifactsParams struct {

	/* AcceptEncoding.

	   Format used to compress your downloaded file. Currently, you must provide the value `gzip`, the only valid format.
	*/
	AcceptEncoding *string

	/* ID.

	   ID of an artifact, such as an IOC pack, PCAP file, memory dump, or actor image. Find an artifact ID in a report or summary.
	*/
	ID string

	/* Name.

	   The name given to your downloaded file.
	*/
	Name *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get artifacts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetArtifactsParams) WithDefaults() *GetArtifactsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get artifacts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetArtifactsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get artifacts params
func (o *GetArtifactsParams) WithTimeout(timeout time.Duration) *GetArtifactsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get artifacts params
func (o *GetArtifactsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get artifacts params
func (o *GetArtifactsParams) WithContext(ctx context.Context) *GetArtifactsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get artifacts params
func (o *GetArtifactsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get artifacts params
func (o *GetArtifactsParams) WithHTTPClient(client *http.Client) *GetArtifactsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get artifacts params
func (o *GetArtifactsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAcceptEncoding adds the acceptEncoding to the get artifacts params
func (o *GetArtifactsParams) WithAcceptEncoding(acceptEncoding *string) *GetArtifactsParams {
	o.SetAcceptEncoding(acceptEncoding)
	return o
}

// SetAcceptEncoding adds the acceptEncoding to the get artifacts params
func (o *GetArtifactsParams) SetAcceptEncoding(acceptEncoding *string) {
	o.AcceptEncoding = acceptEncoding
}

// WithID adds the id to the get artifacts params
func (o *GetArtifactsParams) WithID(id string) *GetArtifactsParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get artifacts params
func (o *GetArtifactsParams) SetID(id string) {
	o.ID = id
}

// WithName adds the name to the get artifacts params
func (o *GetArtifactsParams) WithName(name *string) *GetArtifactsParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the get artifacts params
func (o *GetArtifactsParams) SetName(name *string) {
	o.Name = name
}

// WriteToRequest writes these params to a swagger request
func (o *GetArtifactsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AcceptEncoding != nil {

		// header param Accept-Encoding
		if err := r.SetHeaderParam("Accept-Encoding", *o.AcceptEncoding); err != nil {
			return err
		}
	}

	// query param id
	qrID := o.ID
	qID := qrID
	if qID != "" {

		if err := r.SetQueryParam("id", qID); err != nil {
			return err
		}
	}

	if o.Name != nil {

		// query param name
		var qrName string

		if o.Name != nil {
			qrName = *o.Name
		}
		qName := qrName
		if qName != "" {

			if err := r.SetQueryParam("name", qName); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
