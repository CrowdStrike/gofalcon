// Code generated by go-swagger; DO NOT EDIT.

package foundry_logscale

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

// NewIngestDataParams creates a new IngestDataParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIngestDataParams() *IngestDataParams {
	return &IngestDataParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewIngestDataParamsWithTimeout creates a new IngestDataParams object
// with the ability to set a timeout on a request.
func NewIngestDataParamsWithTimeout(timeout time.Duration) *IngestDataParams {
	return &IngestDataParams{
		timeout: timeout,
	}
}

// NewIngestDataParamsWithContext creates a new IngestDataParams object
// with the ability to set a context for a request.
func NewIngestDataParamsWithContext(ctx context.Context) *IngestDataParams {
	return &IngestDataParams{
		Context: ctx,
	}
}

// NewIngestDataParamsWithHTTPClient creates a new IngestDataParams object
// with the ability to set a custom HTTPClient for a request.
func NewIngestDataParamsWithHTTPClient(client *http.Client) *IngestDataParams {
	return &IngestDataParams{
		HTTPClient: client,
	}
}

/*
IngestDataParams contains all the parameters to send to the API endpoint

	for the ingest data operation.

	Typically these are written to a http.Request.
*/
type IngestDataParams struct {

	/* DataFile.

	   Data file to ingest
	*/
	DataFile runtime.NamedReadCloser

	/* Tag.

	   Custom tag for ingested data in the form tag:value
	*/
	Tag []string

	/* TagSource.

	   Tag the data with the specified source
	*/
	TagSource *string

	/* TestData.

	   Tag the data with test-ingest
	*/
	TestData *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ingest data params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IngestDataParams) WithDefaults() *IngestDataParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ingest data params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IngestDataParams) SetDefaults() {
	var (
		testDataDefault = bool(false)
	)

	val := IngestDataParams{
		TestData: &testDataDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the ingest data params
func (o *IngestDataParams) WithTimeout(timeout time.Duration) *IngestDataParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ingest data params
func (o *IngestDataParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ingest data params
func (o *IngestDataParams) WithContext(ctx context.Context) *IngestDataParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ingest data params
func (o *IngestDataParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ingest data params
func (o *IngestDataParams) WithHTTPClient(client *http.Client) *IngestDataParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ingest data params
func (o *IngestDataParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDataFile adds the dataFile to the ingest data params
func (o *IngestDataParams) WithDataFile(dataFile runtime.NamedReadCloser) *IngestDataParams {
	o.SetDataFile(dataFile)
	return o
}

// SetDataFile adds the dataFile to the ingest data params
func (o *IngestDataParams) SetDataFile(dataFile runtime.NamedReadCloser) {
	o.DataFile = dataFile
}

// WithTag adds the tag to the ingest data params
func (o *IngestDataParams) WithTag(tag []string) *IngestDataParams {
	o.SetTag(tag)
	return o
}

// SetTag adds the tag to the ingest data params
func (o *IngestDataParams) SetTag(tag []string) {
	o.Tag = tag
}

// WithTagSource adds the tagSource to the ingest data params
func (o *IngestDataParams) WithTagSource(tagSource *string) *IngestDataParams {
	o.SetTagSource(tagSource)
	return o
}

// SetTagSource adds the tagSource to the ingest data params
func (o *IngestDataParams) SetTagSource(tagSource *string) {
	o.TagSource = tagSource
}

// WithTestData adds the testData to the ingest data params
func (o *IngestDataParams) WithTestData(testData *bool) *IngestDataParams {
	o.SetTestData(testData)
	return o
}

// SetTestData adds the testData to the ingest data params
func (o *IngestDataParams) SetTestData(testData *bool) {
	o.TestData = testData
}

// WriteToRequest writes these params to a swagger request
func (o *IngestDataParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	// form file param data_file
	if err := r.SetFileParam("data_file", o.DataFile); err != nil {
		return err
	}

	if o.Tag != nil {

		// binding items for tag
		joinedTag := o.bindParamTag(reg)

		// form array param tag
		if err := r.SetFormParam("tag", joinedTag...); err != nil {
			return err
		}
	}

	if o.TagSource != nil {

		// form param tag_source
		var frTagSource string
		if o.TagSource != nil {
			frTagSource = *o.TagSource
		}
		fTagSource := frTagSource
		if fTagSource != "" {
			if err := r.SetFormParam("tag_source", fTagSource); err != nil {
				return err
			}
		}
	}

	if o.TestData != nil {

		// form param test_data
		var frTestData bool
		if o.TestData != nil {
			frTestData = *o.TestData
		}
		fTestData := swag.FormatBool(frTestData)
		if fTestData != "" {
			if err := r.SetFormParam("test_data", fTestData); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamIngestData binds the parameter tag
func (o *IngestDataParams) bindParamTag(formats strfmt.Registry) []string {
	tagIR := o.Tag

	var tagIC []string
	for _, tagIIR := range tagIR { // explode []string

		tagIIV := tagIIR // string as string
		tagIC = append(tagIC, tagIIV)
	}

	// items.CollectionFormat: ""
	tagIS := swag.JoinByFormat(tagIC, "")

	return tagIS
}
