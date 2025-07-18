// Code generated by go-swagger; DO NOT EDIT.

package it_automation

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

// ITAutomationGetTasksByQueryReader is a Reader for the ITAutomationGetTasksByQuery structure.
type ITAutomationGetTasksByQueryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationGetTasksByQueryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationGetTasksByQueryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewITAutomationGetTasksByQueryForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationGetTasksByQueryTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationGetTasksByQueryInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /it-automation/combined/tasks/v1] ITAutomationGetTasksByQuery", response, response.Code())
	}
}

// NewITAutomationGetTasksByQueryOK creates a ITAutomationGetTasksByQueryOK with default headers values
func NewITAutomationGetTasksByQueryOK() *ITAutomationGetTasksByQueryOK {
	return &ITAutomationGetTasksByQueryOK{}
}

/*
ITAutomationGetTasksByQueryOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationGetTasksByQueryOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationGetTaskResponse
}

// IsSuccess returns true when this i t automation get tasks by query o k response has a 2xx status code
func (o *ITAutomationGetTasksByQueryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation get tasks by query o k response has a 3xx status code
func (o *ITAutomationGetTasksByQueryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get tasks by query o k response has a 4xx status code
func (o *ITAutomationGetTasksByQueryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation get tasks by query o k response has a 5xx status code
func (o *ITAutomationGetTasksByQueryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get tasks by query o k response a status code equal to that given
func (o *ITAutomationGetTasksByQueryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation get tasks by query o k response
func (o *ITAutomationGetTasksByQueryOK) Code() int {
	return 200
}

func (o *ITAutomationGetTasksByQueryOK) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryOK  %+v", 200, o.Payload)
}

func (o *ITAutomationGetTasksByQueryOK) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryOK  %+v", 200, o.Payload)
}

func (o *ITAutomationGetTasksByQueryOK) GetPayload() *models.ItautomationGetTaskResponse {
	return o.Payload
}

func (o *ITAutomationGetTasksByQueryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationGetTaskResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationGetTasksByQueryForbidden creates a ITAutomationGetTasksByQueryForbidden with default headers values
func NewITAutomationGetTasksByQueryForbidden() *ITAutomationGetTasksByQueryForbidden {
	return &ITAutomationGetTasksByQueryForbidden{}
}

/*
ITAutomationGetTasksByQueryForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationGetTasksByQueryForbidden struct {

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

// IsSuccess returns true when this i t automation get tasks by query forbidden response has a 2xx status code
func (o *ITAutomationGetTasksByQueryForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get tasks by query forbidden response has a 3xx status code
func (o *ITAutomationGetTasksByQueryForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get tasks by query forbidden response has a 4xx status code
func (o *ITAutomationGetTasksByQueryForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation get tasks by query forbidden response has a 5xx status code
func (o *ITAutomationGetTasksByQueryForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get tasks by query forbidden response a status code equal to that given
func (o *ITAutomationGetTasksByQueryForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation get tasks by query forbidden response
func (o *ITAutomationGetTasksByQueryForbidden) Code() int {
	return 403
}

func (o *ITAutomationGetTasksByQueryForbidden) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationGetTasksByQueryForbidden) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationGetTasksByQueryForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationGetTasksByQueryForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationGetTasksByQueryTooManyRequests creates a ITAutomationGetTasksByQueryTooManyRequests with default headers values
func NewITAutomationGetTasksByQueryTooManyRequests() *ITAutomationGetTasksByQueryTooManyRequests {
	return &ITAutomationGetTasksByQueryTooManyRequests{}
}

/*
ITAutomationGetTasksByQueryTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationGetTasksByQueryTooManyRequests struct {

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

// IsSuccess returns true when this i t automation get tasks by query too many requests response has a 2xx status code
func (o *ITAutomationGetTasksByQueryTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get tasks by query too many requests response has a 3xx status code
func (o *ITAutomationGetTasksByQueryTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get tasks by query too many requests response has a 4xx status code
func (o *ITAutomationGetTasksByQueryTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation get tasks by query too many requests response has a 5xx status code
func (o *ITAutomationGetTasksByQueryTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get tasks by query too many requests response a status code equal to that given
func (o *ITAutomationGetTasksByQueryTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation get tasks by query too many requests response
func (o *ITAutomationGetTasksByQueryTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationGetTasksByQueryTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationGetTasksByQueryTooManyRequests) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationGetTasksByQueryTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationGetTasksByQueryTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationGetTasksByQueryInternalServerError creates a ITAutomationGetTasksByQueryInternalServerError with default headers values
func NewITAutomationGetTasksByQueryInternalServerError() *ITAutomationGetTasksByQueryInternalServerError {
	return &ITAutomationGetTasksByQueryInternalServerError{}
}

/*
ITAutomationGetTasksByQueryInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type ITAutomationGetTasksByQueryInternalServerError struct {

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

// IsSuccess returns true when this i t automation get tasks by query internal server error response has a 2xx status code
func (o *ITAutomationGetTasksByQueryInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get tasks by query internal server error response has a 3xx status code
func (o *ITAutomationGetTasksByQueryInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get tasks by query internal server error response has a 4xx status code
func (o *ITAutomationGetTasksByQueryInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation get tasks by query internal server error response has a 5xx status code
func (o *ITAutomationGetTasksByQueryInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation get tasks by query internal server error response a status code equal to that given
func (o *ITAutomationGetTasksByQueryInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation get tasks by query internal server error response
func (o *ITAutomationGetTasksByQueryInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationGetTasksByQueryInternalServerError) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationGetTasksByQueryInternalServerError) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/tasks/v1][%d] iTAutomationGetTasksByQueryInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationGetTasksByQueryInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationGetTasksByQueryInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
