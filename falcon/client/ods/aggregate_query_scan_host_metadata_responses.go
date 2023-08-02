// Code generated by go-swagger; DO NOT EDIT.

package ods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// AggregateQueryScanHostMetadataReader is a Reader for the AggregateQueryScanHostMetadata structure.
type AggregateQueryScanHostMetadataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AggregateQueryScanHostMetadataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAggregateQueryScanHostMetadataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewAggregateQueryScanHostMetadataForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAggregateQueryScanHostMetadataNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAggregateQueryScanHostMetadataTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /ods/aggregates/scan-hosts/v1] aggregate-query-scan-host-metadata", response, response.Code())
	}
}

// NewAggregateQueryScanHostMetadataOK creates a AggregateQueryScanHostMetadataOK with default headers values
func NewAggregateQueryScanHostMetadataOK() *AggregateQueryScanHostMetadataOK {
	return &AggregateQueryScanHostMetadataOK{}
}

/*
AggregateQueryScanHostMetadataOK describes a response with status code 200, with default header values.

OK
*/
type AggregateQueryScanHostMetadataOK struct {

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

// IsSuccess returns true when this aggregate query scan host metadata o k response has a 2xx status code
func (o *AggregateQueryScanHostMetadataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this aggregate query scan host metadata o k response has a 3xx status code
func (o *AggregateQueryScanHostMetadataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate query scan host metadata o k response has a 4xx status code
func (o *AggregateQueryScanHostMetadataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this aggregate query scan host metadata o k response has a 5xx status code
func (o *AggregateQueryScanHostMetadataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate query scan host metadata o k response a status code equal to that given
func (o *AggregateQueryScanHostMetadataOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the aggregate query scan host metadata o k response
func (o *AggregateQueryScanHostMetadataOK) Code() int {
	return 200
}

func (o *AggregateQueryScanHostMetadataOK) Error() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataOK  %+v", 200, o.Payload)
}

func (o *AggregateQueryScanHostMetadataOK) String() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataOK  %+v", 200, o.Payload)
}

func (o *AggregateQueryScanHostMetadataOK) GetPayload() *models.MsaAggregatesResponse {
	return o.Payload
}

func (o *AggregateQueryScanHostMetadataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateQueryScanHostMetadataForbidden creates a AggregateQueryScanHostMetadataForbidden with default headers values
func NewAggregateQueryScanHostMetadataForbidden() *AggregateQueryScanHostMetadataForbidden {
	return &AggregateQueryScanHostMetadataForbidden{}
}

/*
AggregateQueryScanHostMetadataForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AggregateQueryScanHostMetadataForbidden struct {

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

// IsSuccess returns true when this aggregate query scan host metadata forbidden response has a 2xx status code
func (o *AggregateQueryScanHostMetadataForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate query scan host metadata forbidden response has a 3xx status code
func (o *AggregateQueryScanHostMetadataForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate query scan host metadata forbidden response has a 4xx status code
func (o *AggregateQueryScanHostMetadataForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate query scan host metadata forbidden response has a 5xx status code
func (o *AggregateQueryScanHostMetadataForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate query scan host metadata forbidden response a status code equal to that given
func (o *AggregateQueryScanHostMetadataForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the aggregate query scan host metadata forbidden response
func (o *AggregateQueryScanHostMetadataForbidden) Code() int {
	return 403
}

func (o *AggregateQueryScanHostMetadataForbidden) Error() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataForbidden  %+v", 403, o.Payload)
}

func (o *AggregateQueryScanHostMetadataForbidden) String() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataForbidden  %+v", 403, o.Payload)
}

func (o *AggregateQueryScanHostMetadataForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateQueryScanHostMetadataForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateQueryScanHostMetadataNotFound creates a AggregateQueryScanHostMetadataNotFound with default headers values
func NewAggregateQueryScanHostMetadataNotFound() *AggregateQueryScanHostMetadataNotFound {
	return &AggregateQueryScanHostMetadataNotFound{}
}

/*
AggregateQueryScanHostMetadataNotFound describes a response with status code 404, with default header values.

Not Found
*/
type AggregateQueryScanHostMetadataNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this aggregate query scan host metadata not found response has a 2xx status code
func (o *AggregateQueryScanHostMetadataNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate query scan host metadata not found response has a 3xx status code
func (o *AggregateQueryScanHostMetadataNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate query scan host metadata not found response has a 4xx status code
func (o *AggregateQueryScanHostMetadataNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate query scan host metadata not found response has a 5xx status code
func (o *AggregateQueryScanHostMetadataNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate query scan host metadata not found response a status code equal to that given
func (o *AggregateQueryScanHostMetadataNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the aggregate query scan host metadata not found response
func (o *AggregateQueryScanHostMetadataNotFound) Code() int {
	return 404
}

func (o *AggregateQueryScanHostMetadataNotFound) Error() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataNotFound  %+v", 404, o.Payload)
}

func (o *AggregateQueryScanHostMetadataNotFound) String() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataNotFound  %+v", 404, o.Payload)
}

func (o *AggregateQueryScanHostMetadataNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *AggregateQueryScanHostMetadataNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateQueryScanHostMetadataTooManyRequests creates a AggregateQueryScanHostMetadataTooManyRequests with default headers values
func NewAggregateQueryScanHostMetadataTooManyRequests() *AggregateQueryScanHostMetadataTooManyRequests {
	return &AggregateQueryScanHostMetadataTooManyRequests{}
}

/*
AggregateQueryScanHostMetadataTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type AggregateQueryScanHostMetadataTooManyRequests struct {

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

// IsSuccess returns true when this aggregate query scan host metadata too many requests response has a 2xx status code
func (o *AggregateQueryScanHostMetadataTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this aggregate query scan host metadata too many requests response has a 3xx status code
func (o *AggregateQueryScanHostMetadataTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this aggregate query scan host metadata too many requests response has a 4xx status code
func (o *AggregateQueryScanHostMetadataTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this aggregate query scan host metadata too many requests response has a 5xx status code
func (o *AggregateQueryScanHostMetadataTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this aggregate query scan host metadata too many requests response a status code equal to that given
func (o *AggregateQueryScanHostMetadataTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the aggregate query scan host metadata too many requests response
func (o *AggregateQueryScanHostMetadataTooManyRequests) Code() int {
	return 429
}

func (o *AggregateQueryScanHostMetadataTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataTooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateQueryScanHostMetadataTooManyRequests) String() string {
	return fmt.Sprintf("[POST /ods/aggregates/scan-hosts/v1][%d] aggregateQueryScanHostMetadataTooManyRequests  %+v", 429, o.Payload)
}

func (o *AggregateQueryScanHostMetadataTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateQueryScanHostMetadataTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
