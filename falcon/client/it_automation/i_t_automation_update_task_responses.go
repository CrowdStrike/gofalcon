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

// ITAutomationUpdateTaskReader is a Reader for the ITAutomationUpdateTask structure.
type ITAutomationUpdateTaskReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationUpdateTaskReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationUpdateTaskOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewITAutomationUpdateTaskForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationUpdateTaskTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationUpdateTaskInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /it-automation/entities/tasks/v1] ITAutomationUpdateTask", response, response.Code())
	}
}

// NewITAutomationUpdateTaskOK creates a ITAutomationUpdateTaskOK with default headers values
func NewITAutomationUpdateTaskOK() *ITAutomationUpdateTaskOK {
	return &ITAutomationUpdateTaskOK{}
}

/*
ITAutomationUpdateTaskOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationUpdateTaskOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationUpdateTaskResponse
}

// IsSuccess returns true when this i t automation update task o k response has a 2xx status code
func (o *ITAutomationUpdateTaskOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation update task o k response has a 3xx status code
func (o *ITAutomationUpdateTaskOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update task o k response has a 4xx status code
func (o *ITAutomationUpdateTaskOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update task o k response has a 5xx status code
func (o *ITAutomationUpdateTaskOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update task o k response a status code equal to that given
func (o *ITAutomationUpdateTaskOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation update task o k response
func (o *ITAutomationUpdateTaskOK) Code() int {
	return 200
}

func (o *ITAutomationUpdateTaskOK) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskOK  %+v", 200, o.Payload)
}

func (o *ITAutomationUpdateTaskOK) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskOK  %+v", 200, o.Payload)
}

func (o *ITAutomationUpdateTaskOK) GetPayload() *models.ItautomationUpdateTaskResponse {
	return o.Payload
}

func (o *ITAutomationUpdateTaskOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationUpdateTaskResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationUpdateTaskForbidden creates a ITAutomationUpdateTaskForbidden with default headers values
func NewITAutomationUpdateTaskForbidden() *ITAutomationUpdateTaskForbidden {
	return &ITAutomationUpdateTaskForbidden{}
}

/*
ITAutomationUpdateTaskForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationUpdateTaskForbidden struct {

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

// IsSuccess returns true when this i t automation update task forbidden response has a 2xx status code
func (o *ITAutomationUpdateTaskForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update task forbidden response has a 3xx status code
func (o *ITAutomationUpdateTaskForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update task forbidden response has a 4xx status code
func (o *ITAutomationUpdateTaskForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update task forbidden response has a 5xx status code
func (o *ITAutomationUpdateTaskForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update task forbidden response a status code equal to that given
func (o *ITAutomationUpdateTaskForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation update task forbidden response
func (o *ITAutomationUpdateTaskForbidden) Code() int {
	return 403
}

func (o *ITAutomationUpdateTaskForbidden) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdateTaskForbidden) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationUpdateTaskForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdateTaskForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdateTaskTooManyRequests creates a ITAutomationUpdateTaskTooManyRequests with default headers values
func NewITAutomationUpdateTaskTooManyRequests() *ITAutomationUpdateTaskTooManyRequests {
	return &ITAutomationUpdateTaskTooManyRequests{}
}

/*
ITAutomationUpdateTaskTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationUpdateTaskTooManyRequests struct {

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

// IsSuccess returns true when this i t automation update task too many requests response has a 2xx status code
func (o *ITAutomationUpdateTaskTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update task too many requests response has a 3xx status code
func (o *ITAutomationUpdateTaskTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update task too many requests response has a 4xx status code
func (o *ITAutomationUpdateTaskTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation update task too many requests response has a 5xx status code
func (o *ITAutomationUpdateTaskTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation update task too many requests response a status code equal to that given
func (o *ITAutomationUpdateTaskTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation update task too many requests response
func (o *ITAutomationUpdateTaskTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationUpdateTaskTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdateTaskTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationUpdateTaskTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdateTaskTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationUpdateTaskInternalServerError creates a ITAutomationUpdateTaskInternalServerError with default headers values
func NewITAutomationUpdateTaskInternalServerError() *ITAutomationUpdateTaskInternalServerError {
	return &ITAutomationUpdateTaskInternalServerError{}
}

/*
ITAutomationUpdateTaskInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type ITAutomationUpdateTaskInternalServerError struct {

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

// IsSuccess returns true when this i t automation update task internal server error response has a 2xx status code
func (o *ITAutomationUpdateTaskInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation update task internal server error response has a 3xx status code
func (o *ITAutomationUpdateTaskInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation update task internal server error response has a 4xx status code
func (o *ITAutomationUpdateTaskInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation update task internal server error response has a 5xx status code
func (o *ITAutomationUpdateTaskInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation update task internal server error response a status code equal to that given
func (o *ITAutomationUpdateTaskInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation update task internal server error response
func (o *ITAutomationUpdateTaskInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationUpdateTaskInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdateTaskInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /it-automation/entities/tasks/v1][%d] iTAutomationUpdateTaskInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationUpdateTaskInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationUpdateTaskInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
