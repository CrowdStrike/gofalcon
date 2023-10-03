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

// NewIngestParams creates a new IngestParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIngestParams() *IngestParams {
	return &IngestParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewIngestParamsWithTimeout creates a new IngestParams object
// with the ability to set a timeout on a request.
func NewIngestParamsWithTimeout(timeout time.Duration) *IngestParams {
	return &IngestParams{
		timeout: timeout,
	}
}

// NewIngestParamsWithContext creates a new IngestParams object
// with the ability to set a context for a request.
func NewIngestParamsWithContext(ctx context.Context) *IngestParams {
	return &IngestParams{
		Context: ctx,
	}
}

// NewIngestParamsWithHTTPClient creates a new IngestParams object
// with the ability to set a custom HTTPClient for a request.
func NewIngestParamsWithHTTPClient(client *http.Client) *IngestParams {
	return &IngestParams{
		HTTPClient: client,
	}
}

/*
IngestParams contains all the parameters to send to the API endpoint

	for the ingest operation.

	Typically these are written to a http.Request.
*/
type IngestParams struct {

	/* XCsAppName.

	   App name used to name repository and workflow action
	*/
	XCsAppName *string

	/* DataFile.

	   Data file to ingest.  Currently limited to line delimited JSON
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

// WithDefaults hydrates default values in the ingest params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IngestParams) WithDefaults() *IngestParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ingest params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IngestParams) SetDefaults() {
	var (
		testDataDefault = bool(false)
	)

	val := IngestParams{
		TestData: &testDataDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the ingest params
func (o *IngestParams) WithTimeout(timeout time.Duration) *IngestParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ingest params
func (o *IngestParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ingest params
func (o *IngestParams) WithContext(ctx context.Context) *IngestParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ingest params
func (o *IngestParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ingest params
func (o *IngestParams) WithHTTPClient(client *http.Client) *IngestParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ingest params
func (o *IngestParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithXCsAppName adds the xCsAppName to the ingest params
func (o *IngestParams) WithXCsAppName(xCsAppName *string) *IngestParams {
	o.SetXCsAppName(xCsAppName)
	return o
}

// SetXCsAppName adds the xCsAppName to the ingest params
func (o *IngestParams) SetXCsAppName(xCsAppName *string) {
	o.XCsAppName = xCsAppName
}

// WithDataFile adds the dataFile to the ingest params
func (o *IngestParams) WithDataFile(dataFile runtime.NamedReadCloser) *IngestParams {
	o.SetDataFile(dataFile)
	return o
}

// SetDataFile adds the dataFile to the ingest params
func (o *IngestParams) SetDataFile(dataFile runtime.NamedReadCloser) {
	o.DataFile = dataFile
}

// WithTag adds the tag to the ingest params
func (o *IngestParams) WithTag(tag []string) *IngestParams {
	o.SetTag(tag)
	return o
}

// SetTag adds the tag to the ingest params
func (o *IngestParams) SetTag(tag []string) {
	o.Tag = tag
}

// WithTagSource adds the tagSource to the ingest params
func (o *IngestParams) WithTagSource(tagSource *string) *IngestParams {
	o.SetTagSource(tagSource)
	return o
}

// SetTagSource adds the tagSource to the ingest params
func (o *IngestParams) SetTagSource(tagSource *string) {
	o.TagSource = tagSource
}

// WithTestData adds the testData to the ingest params
func (o *IngestParams) WithTestData(testData *bool) *IngestParams {
	o.SetTestData(testData)
	return o
}

// SetTestData adds the testData to the ingest params
func (o *IngestParams) SetTestData(testData *bool) {
	o.TestData = testData
}

// WriteToRequest writes these params to a swagger request
func (o *IngestParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.XCsAppName != nil {

		// header param X-Cs-App-Name
		if err := r.SetHeaderParam("X-Cs-App-Name", *o.XCsAppName); err != nil {
			return err
		}
	}
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

// bindParamIngest binds the parameter tag
func (o *IngestParams) bindParamTag(formats strfmt.Registry) []string {
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
