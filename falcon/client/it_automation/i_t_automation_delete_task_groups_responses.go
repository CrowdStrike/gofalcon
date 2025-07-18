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

// ITAutomationDeleteTaskGroupsReader is a Reader for the ITAutomationDeleteTaskGroups structure.
type ITAutomationDeleteTaskGroupsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ITAutomationDeleteTaskGroupsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewITAutomationDeleteTaskGroupsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 207:
		result := NewITAutomationDeleteTaskGroupsMultiStatus()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewITAutomationDeleteTaskGroupsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewITAutomationDeleteTaskGroupsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewITAutomationDeleteTaskGroupsConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewITAutomationDeleteTaskGroupsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewITAutomationDeleteTaskGroupsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /it-automation/entities/task-groups/v1] ITAutomationDeleteTaskGroups", response, response.Code())
	}
}

// NewITAutomationDeleteTaskGroupsOK creates a ITAutomationDeleteTaskGroupsOK with default headers values
func NewITAutomationDeleteTaskGroupsOK() *ITAutomationDeleteTaskGroupsOK {
	return &ITAutomationDeleteTaskGroupsOK{}
}

/*
ITAutomationDeleteTaskGroupsOK describes a response with status code 200, with default header values.

OK
*/
type ITAutomationDeleteTaskGroupsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationDeleteTaskGroupsResponse
}

// IsSuccess returns true when this i t automation delete task groups o k response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation delete task groups o k response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups o k response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation delete task groups o k response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete task groups o k response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the i t automation delete task groups o k response
func (o *ITAutomationDeleteTaskGroupsOK) Code() int {
	return 200
}

func (o *ITAutomationDeleteTaskGroupsOK) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsOK  %+v", 200, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsOK) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsOK  %+v", 200, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsOK) GetPayload() *models.ItautomationDeleteTaskGroupsResponse {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationDeleteTaskGroupsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationDeleteTaskGroupsMultiStatus creates a ITAutomationDeleteTaskGroupsMultiStatus with default headers values
func NewITAutomationDeleteTaskGroupsMultiStatus() *ITAutomationDeleteTaskGroupsMultiStatus {
	return &ITAutomationDeleteTaskGroupsMultiStatus{}
}

/*
ITAutomationDeleteTaskGroupsMultiStatus describes a response with status code 207, with default header values.

Multi-Status
*/
type ITAutomationDeleteTaskGroupsMultiStatus struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ItautomationDeleteTaskGroupsResponse
}

// IsSuccess returns true when this i t automation delete task groups multi status response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsMultiStatus) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this i t automation delete task groups multi status response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsMultiStatus) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups multi status response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsMultiStatus) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation delete task groups multi status response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsMultiStatus) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete task groups multi status response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsMultiStatus) IsCode(code int) bool {
	return code == 207
}

// Code gets the status code for the i t automation delete task groups multi status response
func (o *ITAutomationDeleteTaskGroupsMultiStatus) Code() int {
	return 207
}

func (o *ITAutomationDeleteTaskGroupsMultiStatus) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsMultiStatus  %+v", 207, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsMultiStatus) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsMultiStatus  %+v", 207, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsMultiStatus) GetPayload() *models.ItautomationDeleteTaskGroupsResponse {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsMultiStatus) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ItautomationDeleteTaskGroupsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewITAutomationDeleteTaskGroupsBadRequest creates a ITAutomationDeleteTaskGroupsBadRequest with default headers values
func NewITAutomationDeleteTaskGroupsBadRequest() *ITAutomationDeleteTaskGroupsBadRequest {
	return &ITAutomationDeleteTaskGroupsBadRequest{}
}

/*
ITAutomationDeleteTaskGroupsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ITAutomationDeleteTaskGroupsBadRequest struct {

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

// IsSuccess returns true when this i t automation delete task groups bad request response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete task groups bad request response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups bad request response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete task groups bad request response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete task groups bad request response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the i t automation delete task groups bad request response
func (o *ITAutomationDeleteTaskGroupsBadRequest) Code() int {
	return 400
}

func (o *ITAutomationDeleteTaskGroupsBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsBadRequest) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsBadRequest  %+v", 400, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeleteTaskGroupsForbidden creates a ITAutomationDeleteTaskGroupsForbidden with default headers values
func NewITAutomationDeleteTaskGroupsForbidden() *ITAutomationDeleteTaskGroupsForbidden {
	return &ITAutomationDeleteTaskGroupsForbidden{}
}

/*
ITAutomationDeleteTaskGroupsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ITAutomationDeleteTaskGroupsForbidden struct {

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

// IsSuccess returns true when this i t automation delete task groups forbidden response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete task groups forbidden response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups forbidden response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete task groups forbidden response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete task groups forbidden response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the i t automation delete task groups forbidden response
func (o *ITAutomationDeleteTaskGroupsForbidden) Code() int {
	return 403
}

func (o *ITAutomationDeleteTaskGroupsForbidden) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsForbidden) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsForbidden  %+v", 403, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeleteTaskGroupsConflict creates a ITAutomationDeleteTaskGroupsConflict with default headers values
func NewITAutomationDeleteTaskGroupsConflict() *ITAutomationDeleteTaskGroupsConflict {
	return &ITAutomationDeleteTaskGroupsConflict{}
}

/*
ITAutomationDeleteTaskGroupsConflict describes a response with status code 409, with default header values.

Conflict
*/
type ITAutomationDeleteTaskGroupsConflict struct {

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

// IsSuccess returns true when this i t automation delete task groups conflict response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete task groups conflict response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups conflict response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete task groups conflict response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete task groups conflict response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the i t automation delete task groups conflict response
func (o *ITAutomationDeleteTaskGroupsConflict) Code() int {
	return 409
}

func (o *ITAutomationDeleteTaskGroupsConflict) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsConflict  %+v", 409, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsConflict) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsConflict  %+v", 409, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsConflict) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeleteTaskGroupsTooManyRequests creates a ITAutomationDeleteTaskGroupsTooManyRequests with default headers values
func NewITAutomationDeleteTaskGroupsTooManyRequests() *ITAutomationDeleteTaskGroupsTooManyRequests {
	return &ITAutomationDeleteTaskGroupsTooManyRequests{}
}

/*
ITAutomationDeleteTaskGroupsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ITAutomationDeleteTaskGroupsTooManyRequests struct {

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

// IsSuccess returns true when this i t automation delete task groups too many requests response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete task groups too many requests response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups too many requests response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this i t automation delete task groups too many requests response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this i t automation delete task groups too many requests response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the i t automation delete task groups too many requests response
func (o *ITAutomationDeleteTaskGroupsTooManyRequests) Code() int {
	return 429
}

func (o *ITAutomationDeleteTaskGroupsTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewITAutomationDeleteTaskGroupsInternalServerError creates a ITAutomationDeleteTaskGroupsInternalServerError with default headers values
func NewITAutomationDeleteTaskGroupsInternalServerError() *ITAutomationDeleteTaskGroupsInternalServerError {
	return &ITAutomationDeleteTaskGroupsInternalServerError{}
}

/*
ITAutomationDeleteTaskGroupsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ITAutomationDeleteTaskGroupsInternalServerError struct {

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

// IsSuccess returns true when this i t automation delete task groups internal server error response has a 2xx status code
func (o *ITAutomationDeleteTaskGroupsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this i t automation delete task groups internal server error response has a 3xx status code
func (o *ITAutomationDeleteTaskGroupsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this i t automation delete task groups internal server error response has a 4xx status code
func (o *ITAutomationDeleteTaskGroupsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this i t automation delete task groups internal server error response has a 5xx status code
func (o *ITAutomationDeleteTaskGroupsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this i t automation delete task groups internal server error response a status code equal to that given
func (o *ITAutomationDeleteTaskGroupsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the i t automation delete task groups internal server error response
func (o *ITAutomationDeleteTaskGroupsInternalServerError) Code() int {
	return 500
}

func (o *ITAutomationDeleteTaskGroupsInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /it-automation/entities/task-groups/v1][%d] iTAutomationDeleteTaskGroupsInternalServerError  %+v", 500, o.Payload)
}

func (o *ITAutomationDeleteTaskGroupsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ITAutomationDeleteTaskGroupsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
