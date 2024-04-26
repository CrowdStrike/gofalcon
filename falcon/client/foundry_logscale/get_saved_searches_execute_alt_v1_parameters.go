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

// NewGetSavedSearchesExecuteAltV1Params creates a new GetSavedSearchesExecuteAltV1Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetSavedSearchesExecuteAltV1Params() *GetSavedSearchesExecuteAltV1Params {
	return &GetSavedSearchesExecuteAltV1Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetSavedSearchesExecuteAltV1ParamsWithTimeout creates a new GetSavedSearchesExecuteAltV1Params object
// with the ability to set a timeout on a request.
func NewGetSavedSearchesExecuteAltV1ParamsWithTimeout(timeout time.Duration) *GetSavedSearchesExecuteAltV1Params {
	return &GetSavedSearchesExecuteAltV1Params{
		timeout: timeout,
	}
}

// NewGetSavedSearchesExecuteAltV1ParamsWithContext creates a new GetSavedSearchesExecuteAltV1Params object
// with the ability to set a context for a request.
func NewGetSavedSearchesExecuteAltV1ParamsWithContext(ctx context.Context) *GetSavedSearchesExecuteAltV1Params {
	return &GetSavedSearchesExecuteAltV1Params{
		Context: ctx,
	}
}

// NewGetSavedSearchesExecuteAltV1ParamsWithHTTPClient creates a new GetSavedSearchesExecuteAltV1Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetSavedSearchesExecuteAltV1ParamsWithHTTPClient(client *http.Client) *GetSavedSearchesExecuteAltV1Params {
	return &GetSavedSearchesExecuteAltV1Params{
		HTTPClient: client,
	}
}

/*
GetSavedSearchesExecuteAltV1Params contains all the parameters to send to the API endpoint

	for the get saved searches execute alt v1 operation.

	Typically these are written to a http.Request.
*/
type GetSavedSearchesExecuteAltV1Params struct {

	/* AppID.

	   Application ID.
	*/
	AppID *string

	/* InferJSONTypes.

	   Whether to try to infer data types in json event response instead of returning map[string]string
	*/
	InferJSONTypes *bool

	/* JobID.

	   Job ID for a previously executed async query
	*/
	JobID string

	/* Limit.

	   Maximum number of records to return.
	*/
	Limit *string

	/* MatchResponseSchema.

	   Whether to validate search results against their schema
	*/
	MatchResponseSchema *bool

	/* Metadata.

	   Whether to include metadata in the response
	*/
	Metadata *bool

	/* Offset.

	   Starting pagination offset of records to return.
	*/
	Offset *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get saved searches execute alt v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetSavedSearchesExecuteAltV1Params) WithDefaults() *GetSavedSearchesExecuteAltV1Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get saved searches execute alt v1 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetSavedSearchesExecuteAltV1Params) SetDefaults() {
	var (
		inferJSONTypesDefault = bool(false)

		matchResponseSchemaDefault = bool(false)

		metadataDefault = bool(false)
	)

	val := GetSavedSearchesExecuteAltV1Params{
		InferJSONTypes:      &inferJSONTypesDefault,
		MatchResponseSchema: &matchResponseSchemaDefault,
		Metadata:            &metadataDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithTimeout(timeout time.Duration) *GetSavedSearchesExecuteAltV1Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithContext(ctx context.Context) *GetSavedSearchesExecuteAltV1Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithHTTPClient(client *http.Client) *GetSavedSearchesExecuteAltV1Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAppID adds the appID to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithAppID(appID *string) *GetSavedSearchesExecuteAltV1Params {
	o.SetAppID(appID)
	return o
}

// SetAppID adds the appId to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetAppID(appID *string) {
	o.AppID = appID
}

// WithInferJSONTypes adds the inferJSONTypes to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithInferJSONTypes(inferJSONTypes *bool) *GetSavedSearchesExecuteAltV1Params {
	o.SetInferJSONTypes(inferJSONTypes)
	return o
}

// SetInferJSONTypes adds the inferJsonTypes to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetInferJSONTypes(inferJSONTypes *bool) {
	o.InferJSONTypes = inferJSONTypes
}

// WithJobID adds the jobID to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithJobID(jobID string) *GetSavedSearchesExecuteAltV1Params {
	o.SetJobID(jobID)
	return o
}

// SetJobID adds the jobId to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetJobID(jobID string) {
	o.JobID = jobID
}

// WithLimit adds the limit to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithLimit(limit *string) *GetSavedSearchesExecuteAltV1Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetLimit(limit *string) {
	o.Limit = limit
}

// WithMatchResponseSchema adds the matchResponseSchema to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithMatchResponseSchema(matchResponseSchema *bool) *GetSavedSearchesExecuteAltV1Params {
	o.SetMatchResponseSchema(matchResponseSchema)
	return o
}

// SetMatchResponseSchema adds the matchResponseSchema to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetMatchResponseSchema(matchResponseSchema *bool) {
	o.MatchResponseSchema = matchResponseSchema
}

// WithMetadata adds the metadata to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithMetadata(metadata *bool) *GetSavedSearchesExecuteAltV1Params {
	o.SetMetadata(metadata)
	return o
}

// SetMetadata adds the metadata to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetMetadata(metadata *bool) {
	o.Metadata = metadata
}

// WithOffset adds the offset to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) WithOffset(offset *string) *GetSavedSearchesExecuteAltV1Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get saved searches execute alt v1 params
func (o *GetSavedSearchesExecuteAltV1Params) SetOffset(offset *string) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *GetSavedSearchesExecuteAltV1Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AppID != nil {

		// query param app_id
		var qrAppID string

		if o.AppID != nil {
			qrAppID = *o.AppID
		}
		qAppID := qrAppID
		if qAppID != "" {

			if err := r.SetQueryParam("app_id", qAppID); err != nil {
				return err
			}
		}
	}

	if o.InferJSONTypes != nil {

		// query param infer_json_types
		var qrInferJSONTypes bool

		if o.InferJSONTypes != nil {
			qrInferJSONTypes = *o.InferJSONTypes
		}
		qInferJSONTypes := swag.FormatBool(qrInferJSONTypes)
		if qInferJSONTypes != "" {

			if err := r.SetQueryParam("infer_json_types", qInferJSONTypes); err != nil {
				return err
			}
		}
	}

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

	if o.MatchResponseSchema != nil {

		// query param match_response_schema
		var qrMatchResponseSchema bool

		if o.MatchResponseSchema != nil {
			qrMatchResponseSchema = *o.MatchResponseSchema
		}
		qMatchResponseSchema := swag.FormatBool(qrMatchResponseSchema)
		if qMatchResponseSchema != "" {

			if err := r.SetQueryParam("match_response_schema", qMatchResponseSchema); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
