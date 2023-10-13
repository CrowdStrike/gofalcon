// Code generated by go-swagger; DO NOT EDIT.

package sample_uploads

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

// NewArchiveListV1Params creates a new ArchiveListV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArchiveListV1Params() *ArchiveListV1Params {
	return &ArchiveListV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewArchiveListV1ParamsWithTimeout creates a new ArchiveListV1Params object
// with the ability to set a timeout on a request.
func NewArchiveListV1ParamsWithTimeout(timeout time.Duration) *ArchiveListV1Params {
	return &ArchiveListV1Params{
		timeout: timeout,
	}
}

// NewArchiveListV1ParamsWithContext creates a new ArchiveListV1Params object
// with the ability to set a context for a request.
func NewArchiveListV1ParamsWithContext(ctx context.Context) *ArchiveListV1Params {
	return &ArchiveListV1Params{
		Context: ctx,
	}
}

// NewArchiveListV1ParamsWithHTTPClient creates a new ArchiveListV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewArchiveListV1ParamsWithHTTPClient(client *http.Client) *ArchiveListV1Params {
	return &ArchiveListV1Params{
		HTTPClient: client,
	}
}

/* ArchiveListV1Params contains all the parameters to send to the API endpoint
   for the archive list v1 operation.

   Typically these are written to a http.Request.
*/
type ArchiveListV1Params struct {

	/* ID.

	   The archive SHA256.
	*/
	ID string

	/* Limit.

	   Max number of files to retrieve.

	   Default: 100
	*/
	Limit *int64

	/* Offset.

	   Offset from where to get files.
	*/
	Offset *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the archive list v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArchiveListV1Params) WithDefaults() *ArchiveListV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the archive list v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArchiveListV1Params) SetDefaults() {
	var (
		limitDefault = int64(100)
	)

	val := ArchiveListV1Params{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the archive list v1 params
func (o *ArchiveListV1Params) WithTimeout(timeout time.Duration) *ArchiveListV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the archive list v1 params
func (o *ArchiveListV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the archive list v1 params
func (o *ArchiveListV1Params) WithContext(ctx context.Context) *ArchiveListV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the archive list v1 params
func (o *ArchiveListV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the archive list v1 params
func (o *ArchiveListV1Params) WithHTTPClient(client *http.Client) *ArchiveListV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the archive list v1 params
func (o *ArchiveListV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the archive list v1 params
func (o *ArchiveListV1Params) WithID(id string) *ArchiveListV1Params {
	o.SetID(id)
	return o
}

// SetID adds the id to the archive list v1 params
func (o *ArchiveListV1Params) SetID(id string) {
	o.ID = id
}

// WithLimit adds the limit to the archive list v1 params
func (o *ArchiveListV1Params) WithLimit(limit *int64) *ArchiveListV1Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the archive list v1 params
func (o *ArchiveListV1Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the archive list v1 params
func (o *ArchiveListV1Params) WithOffset(offset *string) *ArchiveListV1Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the archive list v1 params
func (o *ArchiveListV1Params) SetOffset(offset *string) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *ArchiveListV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param id
	qrID := o.ID
	qID := qrID
	if qID != "" {

		if err := r.SetQueryParam("id", qID); err != nil {
			return err
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
