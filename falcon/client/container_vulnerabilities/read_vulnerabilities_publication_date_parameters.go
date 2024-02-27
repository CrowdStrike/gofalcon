// Code generated by go-swagger; DO NOT EDIT.

package container_vulnerabilities

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

// NewReadVulnerabilitiesPublicationDateParams creates a new ReadVulnerabilitiesPublicationDateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReadVulnerabilitiesPublicationDateParams() *ReadVulnerabilitiesPublicationDateParams {
	return &ReadVulnerabilitiesPublicationDateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReadVulnerabilitiesPublicationDateParamsWithTimeout creates a new ReadVulnerabilitiesPublicationDateParams object
// with the ability to set a timeout on a request.
func NewReadVulnerabilitiesPublicationDateParamsWithTimeout(timeout time.Duration) *ReadVulnerabilitiesPublicationDateParams {
	return &ReadVulnerabilitiesPublicationDateParams{
		timeout: timeout,
	}
}

// NewReadVulnerabilitiesPublicationDateParamsWithContext creates a new ReadVulnerabilitiesPublicationDateParams object
// with the ability to set a context for a request.
func NewReadVulnerabilitiesPublicationDateParamsWithContext(ctx context.Context) *ReadVulnerabilitiesPublicationDateParams {
	return &ReadVulnerabilitiesPublicationDateParams{
		Context: ctx,
	}
}

// NewReadVulnerabilitiesPublicationDateParamsWithHTTPClient creates a new ReadVulnerabilitiesPublicationDateParams object
// with the ability to set a custom HTTPClient for a request.
func NewReadVulnerabilitiesPublicationDateParamsWithHTTPClient(client *http.Client) *ReadVulnerabilitiesPublicationDateParams {
	return &ReadVulnerabilitiesPublicationDateParams{
		HTTPClient: client,
	}
}

/*
ReadVulnerabilitiesPublicationDateParams contains all the parameters to send to the API endpoint

	for the read vulnerabilities publication date operation.

	Typically these are written to a http.Request.
*/
type ReadVulnerabilitiesPublicationDateParams struct {

	/* Filter.

	   Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filters: cid,cve_id,registry,repository,tag
	*/
	Filter *string

	/* Limit.

	   The upper-bound on the number of records to retrieve.
	*/
	Limit *int64

	/* Offset.

	   The offset from where to begin.
	*/
	Offset *int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the read vulnerabilities publication date params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadVulnerabilitiesPublicationDateParams) WithDefaults() *ReadVulnerabilitiesPublicationDateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the read vulnerabilities publication date params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadVulnerabilitiesPublicationDateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) WithTimeout(timeout time.Duration) *ReadVulnerabilitiesPublicationDateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) WithContext(ctx context.Context) *ReadVulnerabilitiesPublicationDateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) WithHTTPClient(client *http.Client) *ReadVulnerabilitiesPublicationDateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) WithFilter(filter *string) *ReadVulnerabilitiesPublicationDateParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) WithLimit(limit *int64) *ReadVulnerabilitiesPublicationDateParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) WithOffset(offset *int64) *ReadVulnerabilitiesPublicationDateParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the read vulnerabilities publication date params
func (o *ReadVulnerabilitiesPublicationDateParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *ReadVulnerabilitiesPublicationDateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
