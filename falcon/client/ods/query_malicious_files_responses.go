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

	"github.com/aslape/gofalcon/falcon/models"
)

// QueryMaliciousFilesReader is a Reader for the QueryMaliciousFiles structure.
type QueryMaliciousFilesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryMaliciousFilesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryMaliciousFilesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewQueryMaliciousFilesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewQueryMaliciousFilesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryMaliciousFilesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /ods/queries/malicious-files/v1] query-malicious-files", response, response.Code())
	}
}

// NewQueryMaliciousFilesOK creates a QueryMaliciousFilesOK with default headers values
func NewQueryMaliciousFilesOK() *QueryMaliciousFilesOK {
	return &QueryMaliciousFilesOK{}
}

/*
QueryMaliciousFilesOK describes a response with status code 200, with default header values.

OK
*/
type QueryMaliciousFilesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecQueryResponse
}

// IsSuccess returns true when this query malicious files o k response has a 2xx status code
func (o *QueryMaliciousFilesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query malicious files o k response has a 3xx status code
func (o *QueryMaliciousFilesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query malicious files o k response has a 4xx status code
func (o *QueryMaliciousFilesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query malicious files o k response has a 5xx status code
func (o *QueryMaliciousFilesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query malicious files o k response a status code equal to that given
func (o *QueryMaliciousFilesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query malicious files o k response
func (o *QueryMaliciousFilesOK) Code() int {
	return 200
}

func (o *QueryMaliciousFilesOK) Error() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesOK  %+v", 200, o.Payload)
}

func (o *QueryMaliciousFilesOK) String() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesOK  %+v", 200, o.Payload)
}

func (o *QueryMaliciousFilesOK) GetPayload() *models.MsaspecQueryResponse {
	return o.Payload
}

func (o *QueryMaliciousFilesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryMaliciousFilesForbidden creates a QueryMaliciousFilesForbidden with default headers values
func NewQueryMaliciousFilesForbidden() *QueryMaliciousFilesForbidden {
	return &QueryMaliciousFilesForbidden{}
}

/*
QueryMaliciousFilesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryMaliciousFilesForbidden struct {

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

// IsSuccess returns true when this query malicious files forbidden response has a 2xx status code
func (o *QueryMaliciousFilesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query malicious files forbidden response has a 3xx status code
func (o *QueryMaliciousFilesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query malicious files forbidden response has a 4xx status code
func (o *QueryMaliciousFilesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query malicious files forbidden response has a 5xx status code
func (o *QueryMaliciousFilesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query malicious files forbidden response a status code equal to that given
func (o *QueryMaliciousFilesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query malicious files forbidden response
func (o *QueryMaliciousFilesForbidden) Code() int {
	return 403
}

func (o *QueryMaliciousFilesForbidden) Error() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesForbidden  %+v", 403, o.Payload)
}

func (o *QueryMaliciousFilesForbidden) String() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesForbidden  %+v", 403, o.Payload)
}

func (o *QueryMaliciousFilesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryMaliciousFilesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryMaliciousFilesNotFound creates a QueryMaliciousFilesNotFound with default headers values
func NewQueryMaliciousFilesNotFound() *QueryMaliciousFilesNotFound {
	return &QueryMaliciousFilesNotFound{}
}

/*
QueryMaliciousFilesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type QueryMaliciousFilesNotFound struct {

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

// IsSuccess returns true when this query malicious files not found response has a 2xx status code
func (o *QueryMaliciousFilesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query malicious files not found response has a 3xx status code
func (o *QueryMaliciousFilesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query malicious files not found response has a 4xx status code
func (o *QueryMaliciousFilesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this query malicious files not found response has a 5xx status code
func (o *QueryMaliciousFilesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this query malicious files not found response a status code equal to that given
func (o *QueryMaliciousFilesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the query malicious files not found response
func (o *QueryMaliciousFilesNotFound) Code() int {
	return 404
}

func (o *QueryMaliciousFilesNotFound) Error() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesNotFound  %+v", 404, o.Payload)
}

func (o *QueryMaliciousFilesNotFound) String() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesNotFound  %+v", 404, o.Payload)
}

func (o *QueryMaliciousFilesNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryMaliciousFilesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryMaliciousFilesTooManyRequests creates a QueryMaliciousFilesTooManyRequests with default headers values
func NewQueryMaliciousFilesTooManyRequests() *QueryMaliciousFilesTooManyRequests {
	return &QueryMaliciousFilesTooManyRequests{}
}

/*
QueryMaliciousFilesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryMaliciousFilesTooManyRequests struct {

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

// IsSuccess returns true when this query malicious files too many requests response has a 2xx status code
func (o *QueryMaliciousFilesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query malicious files too many requests response has a 3xx status code
func (o *QueryMaliciousFilesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query malicious files too many requests response has a 4xx status code
func (o *QueryMaliciousFilesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query malicious files too many requests response has a 5xx status code
func (o *QueryMaliciousFilesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query malicious files too many requests response a status code equal to that given
func (o *QueryMaliciousFilesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query malicious files too many requests response
func (o *QueryMaliciousFilesTooManyRequests) Code() int {
	return 429
}

func (o *QueryMaliciousFilesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryMaliciousFilesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /ods/queries/malicious-files/v1][%d] queryMaliciousFilesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryMaliciousFilesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryMaliciousFilesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
