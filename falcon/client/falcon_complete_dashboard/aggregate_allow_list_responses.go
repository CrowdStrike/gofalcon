// Code generated by go-swagger; DO NOT EDIT.

package falcon_complete_dashboard

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/aslape/gofalcon/falcon/models"
)

// AggregateAllowListReader is a Reader for the AggregateAllowList structure.
type AggregateAllowListReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AggregateAllowListReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAggregateAllowListOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewAggregateAllowListForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAggregateAllowListTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1] AggregateAllowList", response, response.Code())
	}
}

// NewAggregateAllowListOK creates a AggregateAllowListOK with default headers values
func NewAggregateAllowListOK() *AggregateAllowListOK {
	return &AggregateAllowListOK{}
}

/*
AggregateAllowListOK describes a response with status code 200, with default header values.

OK
*/
type AggregateAllowListOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaAggregatesResponse
}

// IsSuccess returns true when this aggregate allow list o k response has a 2xx status code
func (o *AggregateAllowListOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this aggregate allow list o k response has a 3xx status code
func (o *AggregateAllowListOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate allow list o k response has a 4xx status code
func (o *AggregateAllowListOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this aggregate allow list o k response has a 5xx status code
func (o *AggregateAllowListOK) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate allow list o k response a status code equal to that given
func (o *AggregateAllowListOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the aggregate allow list o k response
func (o *AggregateAllowListOK) Code() int {
	return 200
}

func (o *AggregateAllowListOK) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1][%d] aggregateAllowListOK  %+v", 200, o.Payload)
}

func (o *AggregateAllowListOK) String() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1][%d] aggregateAllowListOK  %+v", 200, o.Payload)
}

func (o *AggregateAllowListOK) GetPayload() *models.MsaAggregatesResponse {
	return o.Payload
}

func (o *AggregateAllowListOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.MsaAggregatesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateAllowListForbidden creates a AggregateAllowListForbidden with default headers values
func NewAggregateAllowListForbidden() *AggregateAllowListForbidden {
	return &AggregateAllowListForbidden{}
}

/*
AggregateAllowListForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AggregateAllowListForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaReplyMetaOnly
}

// IsSuccess returns true when this aggregate allow list forbidden response has a 2xx status code
func (o *AggregateAllowListForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate allow list forbidden response has a 3xx status code
func (o *AggregateAllowListForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate allow list forbidden response has a 4xx status code
func (o *AggregateAllowListForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate allow list forbidden response has a 5xx status code
func (o *AggregateAllowListForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate allow list forbidden response a status code equal to that given
func (o *AggregateAllowListForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the aggregate allow list forbidden response
func (o *AggregateAllowListForbidden) Code() int {
	return 403
}

func (o *AggregateAllowListForbidden) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1][%d] aggregateAllowListForbidden  %+v", 403, o.Payload)
}

func (o *AggregateAllowListForbidden) String() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1][%d] aggregateAllowListForbidden  %+v", 403, o.Payload)
}

func (o *AggregateAllowListForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateAllowListForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.MsaReplyMetaOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateAllowListTooManyRequests creates a AggregateAllowListTooManyRequests with default headers values
func NewAggregateAllowListTooManyRequests() *AggregateAllowListTooManyRequests {
	return &AggregateAllowListTooManyRequests{}
}

/*
AggregateAllowListTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type AggregateAllowListTooManyRequests struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	/* Too many requests, retry after this time (as milliseconds since epoch)
	 */
	XRateLimitRetryAfter int64

	Payload *models.MsaReplyMetaOnly
}

// IsSuccess returns true when this aggregate allow list too many requests response has a 2xx status code
func (o *AggregateAllowListTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate allow list too many requests response has a 3xx status code
func (o *AggregateAllowListTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate allow list too many requests response has a 4xx status code
func (o *AggregateAllowListTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate allow list too many requests response has a 5xx status code
func (o *AggregateAllowListTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate allow list too many requests response a status code equal to that given
func (o *AggregateAllowListTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the aggregate allow list too many requests response
func (o *AggregateAllowListTooManyRequests) Code() int {
	return 429
}

func (o *AggregateAllowListTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1][%d] aggregateAllowListTooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateAllowListTooManyRequests) String() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/allowlist/GET/v1][%d] aggregateAllowListTooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateAllowListTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateAllowListTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	// hydrates response header X-RateLimit-RetryAfter
	hdrXRateLimitRetryAfter := response.GetHeader("X-RateLimit-RetryAfter")

	if hdrXRateLimitRetryAfter != "" {
		valxRateLimitRetryAfter, err := swag.ConvertInt64(hdrXRateLimitRetryAfter)
		if err != nil {
			return errors.InvalidType("X-RateLimit-RetryAfter", "header", "int64", hdrXRateLimitRetryAfter)
		}
		o.XRateLimitRetryAfter = valxRateLimitRetryAfter
	}

	o.Payload = new(models.MsaReplyMetaOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
