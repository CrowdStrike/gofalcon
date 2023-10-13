// Code generated by go-swagger; DO NOT EDIT.

package saved_searches

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

// NewResultParams creates a new ResultParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewResultParams() *ResultParams {
	return &ResultParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewResultParamsWithTimeout creates a new ResultParams object
// with the ability to set a timeout on a request.
func NewResultParamsWithTimeout(timeout time.Duration) *ResultParams {
	return &ResultParams{
		timeout: timeout,
	}
}

// NewResultParamsWithContext creates a new ResultParams object
// with the ability to set a context for a request.
func NewResultParamsWithContext(ctx context.Context) *ResultParams {
	return &ResultParams{
		Context: ctx,
	}
}

// NewResultParamsWithHTTPClient creates a new ResultParams object
// with the ability to set a custom HTTPClient for a request.
func NewResultParamsWithHTTPClient(client *http.Client) *ResultParams {
	return &ResultParams{
		HTTPClient: client,
	}
}

/* ResultParams contains all the parameters to send to the API endpoint
   for the result operation.

   Typically these are written to a http.Request.
*/
type ResultParams struct {

	/* JobID.

	   Job ID for a previously executed async query
	*/
	JobID string

	/* Limit.

	   Maximum number of records to return.
	*/
	Limit *string

	/* Metadata.

	   Whether to include metadata in the response
	*/
	Metadata *bool

	/* Offset.

	   Starting pagination offset of records to return.
	*/
	Offset *string

	/* Version.

	   Version of resource being created
	*/
	Version *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the result params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResultParams) WithDefaults() *ResultParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the result params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResultParams) SetDefaults() {
	var (
		metadataDefault = bool(false)
	)

	val := ResultParams{
		Metadata: &metadataDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the result params
func (o *ResultParams) WithTimeout(timeout time.Duration) *ResultParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the result params
func (o *ResultParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the result params
func (o *ResultParams) WithContext(ctx context.Context) *ResultParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the result params
func (o *ResultParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the result params
func (o *ResultParams) WithHTTPClient(client *http.Client) *ResultParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the result params
func (o *ResultParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithJobID adds the jobID to the result params
func (o *ResultParams) WithJobID(jobID string) *ResultParams {
	o.SetJobID(jobID)
	return o
}

// SetJobID adds the jobId to the result params
func (o *ResultParams) SetJobID(jobID string) {
	o.JobID = jobID
}

// WithLimit adds the limit to the result params
func (o *ResultParams) WithLimit(limit *string) *ResultParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the result params
func (o *ResultParams) SetLimit(limit *string) {
	o.Limit = limit
}

// WithMetadata adds the metadata to the result params
func (o *ResultParams) WithMetadata(metadata *bool) *ResultParams {
	o.SetMetadata(metadata)
	return o
}

// SetMetadata adds the metadata to the result params
func (o *ResultParams) SetMetadata(metadata *bool) {
	o.Metadata = metadata
}

// WithOffset adds the offset to the result params
func (o *ResultParams) WithOffset(offset *string) *ResultParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the result params
func (o *ResultParams) SetOffset(offset *string) {
	o.Offset = offset
}

// WithVersion adds the version to the result params
func (o *ResultParams) WithVersion(version *string) *ResultParams {
	o.SetVersion(version)
	return o
}

// SetVersion adds the version to the result params
func (o *ResultParams) SetVersion(version *string) {
	o.Version = version
}

// WriteToRequest writes these params to a swagger request
func (o *ResultParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param job_id
	qrJobID := o.JobID
	qJobID := qrJobID
	if qJobID != "" {

		if err := r.SetQueryParam("job_id", qJobID); err != nil {
			return err
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit string

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := qrLimit
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Metadata != nil {

		// query param metadata
		var qrMetadata bool

		if o.Metadata != nil {
			qrMetadata = *o.Metadata
		}
		qMetadata := swag.FormatBool(qrMetadata)
		if qMetadata != "" {

			if err := r.SetQueryParam("metadata", qMetadata); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset string

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := qrOffset
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if o.Version != nil {

		// query param version
		var qrVersion string

		if o.Version != nil {
			qrVersion = *o.Version
		}
		qVersion := qrVersion
		if qVersion != "" {

			if err := r.SetQueryParam("version", qVersion); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
