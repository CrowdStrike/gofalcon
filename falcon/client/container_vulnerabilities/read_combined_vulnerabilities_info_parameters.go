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

// NewReadCombinedVulnerabilitiesInfoParams creates a new ReadCombinedVulnerabilitiesInfoParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReadCombinedVulnerabilitiesInfoParams() *ReadCombinedVulnerabilitiesInfoParams {
	return &ReadCombinedVulnerabilitiesInfoParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReadCombinedVulnerabilitiesInfoParamsWithTimeout creates a new ReadCombinedVulnerabilitiesInfoParams object
// with the ability to set a timeout on a request.
func NewReadCombinedVulnerabilitiesInfoParamsWithTimeout(timeout time.Duration) *ReadCombinedVulnerabilitiesInfoParams {
	return &ReadCombinedVulnerabilitiesInfoParams{
		timeout: timeout,
	}
}

// NewReadCombinedVulnerabilitiesInfoParamsWithContext creates a new ReadCombinedVulnerabilitiesInfoParams object
// with the ability to set a context for a request.
func NewReadCombinedVulnerabilitiesInfoParamsWithContext(ctx context.Context) *ReadCombinedVulnerabilitiesInfoParams {
	return &ReadCombinedVulnerabilitiesInfoParams{
		Context: ctx,
	}
}

// NewReadCombinedVulnerabilitiesInfoParamsWithHTTPClient creates a new ReadCombinedVulnerabilitiesInfoParams object
// with the ability to set a custom HTTPClient for a request.
func NewReadCombinedVulnerabilitiesInfoParamsWithHTTPClient(client *http.Client) *ReadCombinedVulnerabilitiesInfoParams {
	return &ReadCombinedVulnerabilitiesInfoParams{
		HTTPClient: client,
	}
}

/*
ReadCombinedVulnerabilitiesInfoParams contains all the parameters to send to the API endpoint

	for the read combined vulnerabilities info operation.

	Typically these are written to a http.Request.
*/
type ReadCombinedVulnerabilitiesInfoParams struct {

	/* CveID.

	   Vulnerability CVE ID
	*/
	CveID string

	/* Limit.

	   The upper-bound on the number of records to retrieve.

	   Default: 100
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

// WithDefaults hydrates default values in the read combined vulnerabilities info params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadCombinedVulnerabilitiesInfoParams) WithDefaults() *ReadCombinedVulnerabilitiesInfoParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the read combined vulnerabilities info params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReadCombinedVulnerabilitiesInfoParams) SetDefaults() {
	var (
		limitDefault = int64(100)
	)

	val := ReadCombinedVulnerabilitiesInfoParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) WithTimeout(timeout time.Duration) *ReadCombinedVulnerabilitiesInfoParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) WithContext(ctx context.Context) *ReadCombinedVulnerabilitiesInfoParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) WithHTTPClient(client *http.Client) *ReadCombinedVulnerabilitiesInfoParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCveID adds the cveID to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) WithCveID(cveID string) *ReadCombinedVulnerabilitiesInfoParams {
	o.SetCveID(cveID)
	return o
}

// SetCveID adds the cveId to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) SetCveID(cveID string) {
	o.CveID = cveID
}

// WithLimit adds the limit to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) WithLimit(limit *int64) *ReadCombinedVulnerabilitiesInfoParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) WithOffset(offset *int64) *ReadCombinedVulnerabilitiesInfoParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the read combined vulnerabilities info params
func (o *ReadCombinedVulnerabilitiesInfoParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *ReadCombinedVulnerabilitiesInfoParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param cve_id
	qrCveID := o.CveID
	qCveID := qrCveID
	if qCveID != "" {

		if err := r.SetQueryParam("cve_id", qCveID); err != nil {
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
