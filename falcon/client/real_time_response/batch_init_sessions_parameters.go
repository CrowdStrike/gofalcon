// Code generated by go-swagger; DO NOT EDIT.

package real_time_response

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

	"github.com/aslape/gofalcon/falcon/models"
)

// NewBatchInitSessionsParams creates a new BatchInitSessionsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBatchInitSessionsParams() *BatchInitSessionsParams {
	return &BatchInitSessionsParams{
		requestTimeout: cr.DefaultTimeout,
	}
}

// NewBatchInitSessionsParamsWithTimeout creates a new BatchInitSessionsParams object
// with the ability to set a timeout on a request.
func NewBatchInitSessionsParamsWithTimeout(timeout time.Duration) *BatchInitSessionsParams {
	return &BatchInitSessionsParams{
		requestTimeout: timeout,
	}
}

// NewBatchInitSessionsParamsWithContext creates a new BatchInitSessionsParams object
// with the ability to set a context for a request.
func NewBatchInitSessionsParamsWithContext(ctx context.Context) *BatchInitSessionsParams {
	return &BatchInitSessionsParams{
		Context: ctx,
	}
}

// NewBatchInitSessionsParamsWithHTTPClient creates a new BatchInitSessionsParams object
// with the ability to set a custom HTTPClient for a request.
func NewBatchInitSessionsParamsWithHTTPClient(client *http.Client) *BatchInitSessionsParams {
	return &BatchInitSessionsParams{
		HTTPClient: client,
	}
}

/*
BatchInitSessionsParams contains all the parameters to send to the API endpoint

	for the batch init sessions operation.

	Typically these are written to a http.Request.
*/
type BatchInitSessionsParams struct {

	/* Body.

	     **`host_ids`** List of host agent ID's to initialize a RTR session on. A maximum of 10000 hosts can be in a single batch session.
	**`existing_batch_id`** Optional batch ID. Use an existing batch ID if you want to initialize new hosts and add them to the existing batch
	**`queue_offline`** If we should queue this session if the host is offline.  Any commands run against an offline-queued session will be queued up and executed when the host comes online.
	*/
	Body *models.DomainBatchInitSessionRequest

	/* HostTimeoutDuration.

	   Timeout duration for how long a host has time to complete processing. Default value is a bit less than the overall timeout value. It cannot be greater than the overall request timeout. Maximum is < 5 minutes. Example, `10s`. Valid units: `ns, us, ms, s, m, h`.

	   Default: "tiny bit less than overall request timeout"
	*/
	HostTimeoutDuration *string

	/* Timeout.

	   Timeout for how long to wait for the request in seconds, default timeout is 30 seconds. Maximum is 5 minutes.

	   Default: 30
	*/
	Timeout *int64

	/* TimeoutDuration.

	   Timeout duration for how long to wait for the request in duration syntax. Example, `10s`. Valid units: `ns, us, ms, s, m, h`. Maximum is 5 minutes.

	   Default: "30s"
	*/
	TimeoutDuration *string

	requestTimeout time.Duration
	Context        context.Context
	HTTPClient     *http.Client
}

// WithDefaults hydrates default values in the batch init sessions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BatchInitSessionsParams) WithDefaults() *BatchInitSessionsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the batch init sessions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BatchInitSessionsParams) SetDefaults() {
	var (
		hostTimeoutDurationDefault = string("tiny bit less than overall request timeout")

		timeoutDefault = int64(30)

		timeoutDurationDefault = string("30s")
	)

	val := BatchInitSessionsParams{
		HostTimeoutDuration: &hostTimeoutDurationDefault,
		Timeout:             &timeoutDefault,
		TimeoutDuration:     &timeoutDurationDefault,
	}

	val.requestTimeout = o.requestTimeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithRequestTimeout adds the timeout to the batch init sessions params
func (o *BatchInitSessionsParams) WithRequestTimeout(timeout time.Duration) *BatchInitSessionsParams {
	o.SetRequestTimeout(timeout)
	return o
}

// SetRequestTimeout adds the timeout to the batch init sessions params
func (o *BatchInitSessionsParams) SetRequestTimeout(timeout time.Duration) {
	o.requestTimeout = timeout
}

// WithContext adds the context to the batch init sessions params
func (o *BatchInitSessionsParams) WithContext(ctx context.Context) *BatchInitSessionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the batch init sessions params
func (o *BatchInitSessionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the batch init sessions params
func (o *BatchInitSessionsParams) WithHTTPClient(client *http.Client) *BatchInitSessionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the batch init sessions params
func (o *BatchInitSessionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the batch init sessions params
func (o *BatchInitSessionsParams) WithBody(body *models.DomainBatchInitSessionRequest) *BatchInitSessionsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the batch init sessions params
func (o *BatchInitSessionsParams) SetBody(body *models.DomainBatchInitSessionRequest) {
	o.Body = body
}

// WithHostTimeoutDuration adds the hostTimeoutDuration to the batch init sessions params
func (o *BatchInitSessionsParams) WithHostTimeoutDuration(hostTimeoutDuration *string) *BatchInitSessionsParams {
	o.SetHostTimeoutDuration(hostTimeoutDuration)
	return o
}

// SetHostTimeoutDuration adds the hostTimeoutDuration to the batch init sessions params
func (o *BatchInitSessionsParams) SetHostTimeoutDuration(hostTimeoutDuration *string) {
	o.HostTimeoutDuration = hostTimeoutDuration
}

// WithTimeout adds the timeout to the batch init sessions params
func (o *BatchInitSessionsParams) WithTimeout(timeout *int64) *BatchInitSessionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the batch init sessions params
func (o *BatchInitSessionsParams) SetTimeout(timeout *int64) {
	o.Timeout = timeout
}

// WithTimeoutDuration adds the timeoutDuration to the batch init sessions params
func (o *BatchInitSessionsParams) WithTimeoutDuration(timeoutDuration *string) *BatchInitSessionsParams {
	o.SetTimeoutDuration(timeoutDuration)
	return o
}

// SetTimeoutDuration adds the timeoutDuration to the batch init sessions params
func (o *BatchInitSessionsParams) SetTimeoutDuration(timeoutDuration *string) {
	o.TimeoutDuration = timeoutDuration
}

// WriteToRequest writes these params to a swagger request
func (o *BatchInitSessionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.requestTimeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if o.HostTimeoutDuration != nil {

		// query param host_timeout_duration
		var qrHostTimeoutDuration string

		if o.HostTimeoutDuration != nil {
			qrHostTimeoutDuration = *o.HostTimeoutDuration
		}
		qHostTimeoutDuration := qrHostTimeoutDuration
		if qHostTimeoutDuration != "" {

			if err := r.SetQueryParam("host_timeout_duration", qHostTimeoutDuration); err != nil {
				return err
			}
		}
	}

	if o.Timeout != nil {

		// query param timeout
		var qrTimeout int64

		if o.Timeout != nil {
			qrTimeout = *o.Timeout
		}
		qTimeout := swag.FormatInt64(qrTimeout)
		if qTimeout != "" {

			if err := r.SetQueryParam("timeout", qTimeout); err != nil {
				return err
			}
		}
	}

	if o.TimeoutDuration != nil {

		// query param timeout_duration
		var qrTimeoutDuration string

		if o.TimeoutDuration != nil {
			qrTimeoutDuration = *o.TimeoutDuration
		}
		qTimeoutDuration := qrTimeoutDuration
		if qTimeoutDuration != "" {

			if err := r.SetQueryParam("timeout_duration", qTimeoutDuration); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
