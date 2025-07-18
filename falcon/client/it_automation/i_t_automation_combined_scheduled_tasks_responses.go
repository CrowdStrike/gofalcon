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

// ITAutomationCombinedScheduledTasksReader is a Reader for the ITAutomationCombinedScheduledTasks structure.
type ITAutomationCombinedScheduledTasksReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationCombinedScheduledTasksReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationCombinedScheduledTasksOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationCombinedScheduledTasksBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationCombinedScheduledTasksForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationCombinedScheduledTasksTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationCombinedScheduledTasksInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /it-automation/combined/scheduled-tasks/v1] ITAutomationCombinedScheduledTasks", response, response.Code())
	}
}

// NewITAutomationCombinedScheduledTasksOK creates a ITAutomationCombinedScheduledTasksOK with default headers values
func NewITAutomationCombinedScheduledTasksOK() *ITAutomationCombinedScheduledTasksOK {
	return &ITAutomationCombinedScheduledTasksOK{}
}

/*
ITAutomationCombinedScheduledTasksOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationCombinedScheduledTasksOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationGetScheduledTaskResponse
}

// IsSuccess returns true when this i t automation combined scheduled tasks o k response has a 2xx status code
func (o *ITAutomationCombinedScheduledTasksOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation combined scheduled tasks o k response has a 3xx status code
func (o *ITAutomationCombinedScheduledTasksOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation combined scheduled tasks o k response has a 4xx status code
func (o *ITAutomationCombinedScheduledTasksOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation combined scheduled tasks o k response has a 5xx status code
func (o *ITAutomationCombinedScheduledTasksOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation combined scheduled tasks o k response a status code equal to that given
func (o *ITAutomationCombinedScheduledTasksOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation combined scheduled tasks o k response
func (o *ITAutomationCombinedScheduledTasksOK) Code() int {
	return 200
}

func (o *ITAutomationCombinedScheduledTasksOK) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksOK  %+v", 200, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksOK) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksOK  %+v", 200, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksOK) GetPayload() *models.ItautomationGetScheduledTaskResponse {
	return o.Payload
}

func (o *ITAutomationCombinedScheduledTasksOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationGetScheduledTaskResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationCombinedScheduledTasksBadRequest creates a ITAutomationCombinedScheduledTasksBadRequest with default headers values
func NewITAutomationCombinedScheduledTasksBadRequest() *ITAutomationCombinedScheduledTasksBadRequest {
	return &ITAutomationCombinedScheduledTasksBadRequest{}
}

/*
ITAutomationCombinedScheduledTasksBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationCombinedScheduledTasksBadRequest struct {

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

// IsSuccess returns true when this i t automation combined scheduled tasks bad request response has a 2xx status code
func (o *ITAutomationCombinedScheduledTasksBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation combined scheduled tasks bad request response has a 3xx status code
func (o *ITAutomationCombinedScheduledTasksBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation combined scheduled tasks bad request response has a 4xx status code
func (o *ITAutomationCombinedScheduledTasksBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation combined scheduled tasks bad request response has a 5xx status code
func (o *ITAutomationCombinedScheduledTasksBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation combined scheduled tasks bad request response a status code equal to that given
func (o *ITAutomationCombinedScheduledTasksBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation combined scheduled tasks bad request response
func (o *ITAutomationCombinedScheduledTasksBadRequest) Code() int {
	return 400
}

func (o *ITAutomationCombinedScheduledTasksBadRequest) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksBadRequest) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationCombinedScheduledTasksBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationCombinedScheduledTasksForbidden creates a ITAutomationCombinedScheduledTasksForbidden with default headers values
func NewITAutomationCombinedScheduledTasksForbidden() *ITAutomationCombinedScheduledTasksForbidden {
	return &ITAutomationCombinedScheduledTasksForbidden{}
}

/*
ITAutomationCombinedScheduledTasksForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationCombinedScheduledTasksForbidden struct {

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

// IsSuccess returns true when this i t automation combined scheduled tasks forbidden response has a 2xx status code
func (o *ITAutomationCombinedScheduledTasksForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation combined scheduled tasks forbidden response has a 3xx status code
func (o *ITAutomationCombinedScheduledTasksForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation combined scheduled tasks forbidden response has a 4xx status code
func (o *ITAutomationCombinedScheduledTasksForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation combined scheduled tasks forbidden response has a 5xx status code
func (o *ITAutomationCombinedScheduledTasksForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation combined scheduled tasks forbidden response a status code equal to that given
func (o *ITAutomationCombinedScheduledTasksForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation combined scheduled tasks forbidden response
func (o *ITAutomationCombinedScheduledTasksForbidden) Code() int {
	return 403
}

func (o *ITAutomationCombinedScheduledTasksForbidden) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksForbidden) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationCombinedScheduledTasksForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationCombinedScheduledTasksTooManyRequests creates a ITAutomationCombinedScheduledTasksTooManyRequests with default headers values
func NewITAutomationCombinedScheduledTasksTooManyRequests() *ITAutomationCombinedScheduledTasksTooManyRequests {
	return &ITAutomationCombinedScheduledTasksTooManyRequests{}
}

/*
ITAutomationCombinedScheduledTasksTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationCombinedScheduledTasksTooManyRequests struct {

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

// IsSuccess returns true when this i t automation combined scheduled tasks too many requests response has a 2xx status code
func (o *ITAutomationCombinedScheduledTasksTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation combined scheduled tasks too many requests response has a 3xx status code
func (o *ITAutomationCombinedScheduledTasksTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation combined scheduled tasks too many requests response has a 4xx status code
func (o *ITAutomationCombinedScheduledTasksTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation combined scheduled tasks too many requests response has a 5xx status code
func (o *ITAutomationCombinedScheduledTasksTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation combined scheduled tasks too many requests response a status code equal to that given
func (o *ITAutomationCombinedScheduledTasksTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation combined scheduled tasks too many requests response
func (o *ITAutomationCombinedScheduledTasksTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationCombinedScheduledTasksTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksTooManyRequests) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationCombinedScheduledTasksTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationCombinedScheduledTasksInternalServerError creates a ITAutomationCombinedScheduledTasksInternalServerError with default headers values
func NewITAutomationCombinedScheduledTasksInternalServerError() *ITAutomationCombinedScheduledTasksInternalServerError {
	return &ITAutomationCombinedScheduledTasksInternalServerError{}
}

/*
ITAutomationCombinedScheduledTasksInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationCombinedScheduledTasksInternalServerError struct {

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

// IsSuccess returns true when this i t automation combined scheduled tasks internal server error response has a 2xx status code
func (o *ITAutomationCombinedScheduledTasksInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation combined scheduled tasks internal server error response has a 3xx status code
func (o *ITAutomationCombinedScheduledTasksInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation combined scheduled tasks internal server error response has a 4xx status code
func (o *ITAutomationCombinedScheduledTasksInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation combined scheduled tasks internal server error response has a 5xx status code
func (o *ITAutomationCombinedScheduledTasksInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation combined scheduled tasks internal server error response a status code equal to that given
func (o *ITAutomationCombinedScheduledTasksInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation combined scheduled tasks internal server error response
func (o *ITAutomationCombinedScheduledTasksInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationCombinedScheduledTasksInternalServerError) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksInternalServerError) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/scheduled-tasks/v1][%d] iTAutomationCombinedScheduledTasksInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationCombinedScheduledTasksInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationCombinedScheduledTasksInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
