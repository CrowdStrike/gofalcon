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

// ITAutomationGetTaskGroupsByQueryReader is a Reader for the ITAutomationGetTaskGroupsByQuery structure.
type ITAutomationGetTaskGroupsByQueryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationGetTaskGroupsByQueryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationGetTaskGroupsByQueryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewITAutomationGetTaskGroupsByQueryMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationGetTaskGroupsByQueryBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationGetTaskGroupsByQueryForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationGetTaskGroupsByQueryTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationGetTaskGroupsByQueryInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /it-automation/combined/task-groups/v1] ITAutomationGetTaskGroupsByQuery", response, response.Code())
	}
}

// NewITAutomationGetTaskGroupsByQueryOK creates a ITAutomationGetTaskGroupsByQueryOK with default headers values
func NewITAutomationGetTaskGroupsByQueryOK() *ITAutomationGetTaskGroupsByQueryOK {
	return &ITAutomationGetTaskGroupsByQueryOK{}
}

/*
ITAutomationGetTaskGroupsByQueryOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationGetTaskGroupsByQueryOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationGetTaskGroupsResponse
}

// IsSuccess returns true when this i t automation get task groups by query o k response has a 2xx status code
func (o *ITAutomationGetTaskGroupsByQueryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation get task groups by query o k response has a 3xx status code
func (o *ITAutomationGetTaskGroupsByQueryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get task groups by query o k response has a 4xx status code
func (o *ITAutomationGetTaskGroupsByQueryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation get task groups by query o k response has a 5xx status code
func (o *ITAutomationGetTaskGroupsByQueryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get task groups by query o k response a status code equal to that given
func (o *ITAutomationGetTaskGroupsByQueryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation get task groups by query o k response
func (o *ITAutomationGetTaskGroupsByQueryOK) Code() int {
	return 200
}

func (o *ITAutomationGetTaskGroupsByQueryOK) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryOK  %+v", 200, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryOK) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryOK  %+v", 200, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryOK) GetPayload() *models.ItautomationGetTaskGroupsResponse {
	return o.Payload
}

func (o *ITAutomationGetTaskGroupsByQueryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationGetTaskGroupsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationGetTaskGroupsByQueryMultiStatus creates a ITAutomationGetTaskGroupsByQueryMultiStatus with default headers values
func NewITAutomationGetTaskGroupsByQueryMultiStatus() *ITAutomationGetTaskGroupsByQueryMultiStatus {
	return &ITAutomationGetTaskGroupsByQueryMultiStatus{}
}

/*
ITAutomationGetTaskGroupsByQueryMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type ITAutomationGetTaskGroupsByQueryMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationGetTaskGroupsResponse
}

// IsSuccess returns true when this i t automation get task groups by query multi status response has a 2xx status code
func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation get task groups by query multi status response has a 3xx status code
func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get task groups by query multi status response has a 4xx status code
func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation get task groups by query multi status response has a 5xx status code
func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get task groups by query multi status response a status code equal to that given
func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the i t automation get task groups by query multi status response
func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) Code() int {
	return 207
}

func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryMultiStatus  %+v", 207, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryMultiStatus  %+v", 207, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) GetPayload() *models.ItautomationGetTaskGroupsResponse {
	return o.Payload
}

func (o *ITAutomationGetTaskGroupsByQueryMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationGetTaskGroupsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationGetTaskGroupsByQueryBadRequest creates a ITAutomationGetTaskGroupsByQueryBadRequest with default headers values
func NewITAutomationGetTaskGroupsByQueryBadRequest() *ITAutomationGetTaskGroupsByQueryBadRequest {
	return &ITAutomationGetTaskGroupsByQueryBadRequest{}
}

/*
ITAutomationGetTaskGroupsByQueryBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationGetTaskGroupsByQueryBadRequest struct {

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

// IsSuccess returns true when this i t automation get task groups by query bad request response has a 2xx status code
func (o *ITAutomationGetTaskGroupsByQueryBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get task groups by query bad request response has a 3xx status code
func (o *ITAutomationGetTaskGroupsByQueryBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get task groups by query bad request response has a 4xx status code
func (o *ITAutomationGetTaskGroupsByQueryBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation get task groups by query bad request response has a 5xx status code
func (o *ITAutomationGetTaskGroupsByQueryBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get task groups by query bad request response a status code equal to that given
func (o *ITAutomationGetTaskGroupsByQueryBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation get task groups by query bad request response
func (o *ITAutomationGetTaskGroupsByQueryBadRequest) Code() int {
	return 400
}

func (o *ITAutomationGetTaskGroupsByQueryBadRequest) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryBadRequest) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationGetTaskGroupsByQueryBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationGetTaskGroupsByQueryForbidden creates a ITAutomationGetTaskGroupsByQueryForbidden with default headers values
func NewITAutomationGetTaskGroupsByQueryForbidden() *ITAutomationGetTaskGroupsByQueryForbidden {
	return &ITAutomationGetTaskGroupsByQueryForbidden{}
}

/*
ITAutomationGetTaskGroupsByQueryForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationGetTaskGroupsByQueryForbidden struct {

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

// IsSuccess returns true when this i t automation get task groups by query forbidden response has a 2xx status code
func (o *ITAutomationGetTaskGroupsByQueryForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get task groups by query forbidden response has a 3xx status code
func (o *ITAutomationGetTaskGroupsByQueryForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get task groups by query forbidden response has a 4xx status code
func (o *ITAutomationGetTaskGroupsByQueryForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation get task groups by query forbidden response has a 5xx status code
func (o *ITAutomationGetTaskGroupsByQueryForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get task groups by query forbidden response a status code equal to that given
func (o *ITAutomationGetTaskGroupsByQueryForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation get task groups by query forbidden response
func (o *ITAutomationGetTaskGroupsByQueryForbidden) Code() int {
	return 403
}

func (o *ITAutomationGetTaskGroupsByQueryForbidden) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryForbidden) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationGetTaskGroupsByQueryForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationGetTaskGroupsByQueryTooManyRequests creates a ITAutomationGetTaskGroupsByQueryTooManyRequests with default headers values
func NewITAutomationGetTaskGroupsByQueryTooManyRequests() *ITAutomationGetTaskGroupsByQueryTooManyRequests {
	return &ITAutomationGetTaskGroupsByQueryTooManyRequests{}
}

/*
ITAutomationGetTaskGroupsByQueryTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationGetTaskGroupsByQueryTooManyRequests struct {

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

// IsSuccess returns true when this i t automation get task groups by query too many requests response has a 2xx status code
func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get task groups by query too many requests response has a 3xx status code
func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get task groups by query too many requests response has a 4xx status code
func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation get task groups by query too many requests response has a 5xx status code
func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation get task groups by query too many requests response a status code equal to that given
func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation get task groups by query too many requests response
func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationGetTaskGroupsByQueryTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationGetTaskGroupsByQueryInternalServerError creates a ITAutomationGetTaskGroupsByQueryInternalServerError with default headers values
func NewITAutomationGetTaskGroupsByQueryInternalServerError() *ITAutomationGetTaskGroupsByQueryInternalServerError {
	return &ITAutomationGetTaskGroupsByQueryInternalServerError{}
}

/*
ITAutomationGetTaskGroupsByQueryInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationGetTaskGroupsByQueryInternalServerError struct {

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

// IsSuccess returns true when this i t automation get task groups by query internal server error response has a 2xx status code
func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation get task groups by query internal server error response has a 3xx status code
func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation get task groups by query internal server error response has a 4xx status code
func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation get task groups by query internal server error response has a 5xx status code
func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation get task groups by query internal server error response a status code equal to that given
func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation get task groups by query internal server error response
func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) Error() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) String() string {
	return fmt.Sprintf("[GET /it-automation/combined/task-groups/v1][%d] iTAutomationGetTaskGroupsByQueryInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationGetTaskGroupsByQueryInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
