// Code generated by go-swagger; DO NOT EDIT.

package workflows

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

// WorkflowActivitiesCombinedReader is a Reader for the WorkflowActivitiesCombined structure.
type WorkflowActivitiesCombinedReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *WorkflowActivitiesCombinedReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewWorkflowActivitiesCombinedOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewWorkflowActivitiesCombinedBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewWorkflowActivitiesCombinedForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewWorkflowActivitiesCombinedNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewWorkflowActivitiesCombinedTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewWorkflowActivitiesCombinedInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /workflows/combined/activities/v1] WorkflowActivitiesCombined", response, response.Code())
	}
}

// NewWorkflowActivitiesCombinedOK creates a WorkflowActivitiesCombinedOK with default headers values
func NewWorkflowActivitiesCombinedOK() *WorkflowActivitiesCombinedOK {
	return &WorkflowActivitiesCombinedOK{}
}

/*
WorkflowActivitiesCombinedOK describes a response with status code 200, with default header values.

OK
*/
type WorkflowActivitiesCombinedOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ActivitiesLegacyActivityExternalResponse
}

// IsSuccess returns true when this workflow activities combined o k response has a 2xx status code
func (o *WorkflowActivitiesCombinedOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this workflow activities combined o k response has a 3xx status code
func (o *WorkflowActivitiesCombinedOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow activities combined o k response has a 4xx status code
func (o *WorkflowActivitiesCombinedOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this workflow activities combined o k response has a 5xx status code
func (o *WorkflowActivitiesCombinedOK) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow activities combined o k response a status code equal to that given
func (o *WorkflowActivitiesCombinedOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the workflow activities combined o k response
func (o *WorkflowActivitiesCombinedOK) Code() int {
	return 200
}

func (o *WorkflowActivitiesCombinedOK) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedOK  %+v", 200, o.Payload)
}

func (o *WorkflowActivitiesCombinedOK) String() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedOK  %+v", 200, o.Payload)
}

func (o *WorkflowActivitiesCombinedOK) GetPayload() *models.ActivitiesLegacyActivityExternalResponse {
	return o.Payload
}

func (o *WorkflowActivitiesCombinedOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ActivitiesLegacyActivityExternalResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowActivitiesCombinedBadRequest creates a WorkflowActivitiesCombinedBadRequest with default headers values
func NewWorkflowActivitiesCombinedBadRequest() *WorkflowActivitiesCombinedBadRequest {
	return &WorkflowActivitiesCombinedBadRequest{}
}

/*
WorkflowActivitiesCombinedBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type WorkflowActivitiesCombinedBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ActivitiesLegacyActivityExternalResponse
}

// IsSuccess returns true when this workflow activities combined bad request response has a 2xx status code
func (o *WorkflowActivitiesCombinedBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow activities combined bad request response has a 3xx status code
func (o *WorkflowActivitiesCombinedBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow activities combined bad request response has a 4xx status code
func (o *WorkflowActivitiesCombinedBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow activities combined bad request response has a 5xx status code
func (o *WorkflowActivitiesCombinedBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow activities combined bad request response a status code equal to that given
func (o *WorkflowActivitiesCombinedBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the workflow activities combined bad request response
func (o *WorkflowActivitiesCombinedBadRequest) Code() int {
	return 400
}

func (o *WorkflowActivitiesCombinedBadRequest) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedBadRequest  %+v", 400, o.Payload)
}

func (o *WorkflowActivitiesCombinedBadRequest) String() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedBadRequest  %+v", 400, o.Payload)
}

func (o *WorkflowActivitiesCombinedBadRequest) GetPayload() *models.ActivitiesLegacyActivityExternalResponse {
	return o.Payload
}

func (o *WorkflowActivitiesCombinedBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ActivitiesLegacyActivityExternalResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowActivitiesCombinedForbidden creates a WorkflowActivitiesCombinedForbidden with default headers values
func NewWorkflowActivitiesCombinedForbidden() *WorkflowActivitiesCombinedForbidden {
	return &WorkflowActivitiesCombinedForbidden{}
}

/*
WorkflowActivitiesCombinedForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type WorkflowActivitiesCombinedForbidden struct {

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

// IsSuccess returns true when this workflow activities combined forbidden response has a 2xx status code
func (o *WorkflowActivitiesCombinedForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow activities combined forbidden response has a 3xx status code
func (o *WorkflowActivitiesCombinedForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow activities combined forbidden response has a 4xx status code
func (o *WorkflowActivitiesCombinedForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow activities combined forbidden response has a 5xx status code
func (o *WorkflowActivitiesCombinedForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow activities combined forbidden response a status code equal to that given
func (o *WorkflowActivitiesCombinedForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the workflow activities combined forbidden response
func (o *WorkflowActivitiesCombinedForbidden) Code() int {
	return 403
}

func (o *WorkflowActivitiesCombinedForbidden) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedForbidden  %+v", 403, o.Payload)
}

func (o *WorkflowActivitiesCombinedForbidden) String() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedForbidden  %+v", 403, o.Payload)
}

func (o *WorkflowActivitiesCombinedForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *WorkflowActivitiesCombinedForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewWorkflowActivitiesCombinedNotFound creates a WorkflowActivitiesCombinedNotFound with default headers values
func NewWorkflowActivitiesCombinedNotFound() *WorkflowActivitiesCombinedNotFound {
	return &WorkflowActivitiesCombinedNotFound{}
}

/*
WorkflowActivitiesCombinedNotFound describes a response with status code 404, with default header values.

Not Found
*/
type WorkflowActivitiesCombinedNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ActivitiesLegacyActivityExternalResponse
}

// IsSuccess returns true when this workflow activities combined not found response has a 2xx status code
func (o *WorkflowActivitiesCombinedNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow activities combined not found response has a 3xx status code
func (o *WorkflowActivitiesCombinedNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow activities combined not found response has a 4xx status code
func (o *WorkflowActivitiesCombinedNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow activities combined not found response has a 5xx status code
func (o *WorkflowActivitiesCombinedNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow activities combined not found response a status code equal to that given
func (o *WorkflowActivitiesCombinedNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the workflow activities combined not found response
func (o *WorkflowActivitiesCombinedNotFound) Code() int {
	return 404
}

func (o *WorkflowActivitiesCombinedNotFound) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedNotFound  %+v", 404, o.Payload)
}

func (o *WorkflowActivitiesCombinedNotFound) String() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedNotFound  %+v", 404, o.Payload)
}

func (o *WorkflowActivitiesCombinedNotFound) GetPayload() *models.ActivitiesLegacyActivityExternalResponse {
	return o.Payload
}

func (o *WorkflowActivitiesCombinedNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ActivitiesLegacyActivityExternalResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowActivitiesCombinedTooManyRequests creates a WorkflowActivitiesCombinedTooManyRequests with default headers values
func NewWorkflowActivitiesCombinedTooManyRequests() *WorkflowActivitiesCombinedTooManyRequests {
	return &WorkflowActivitiesCombinedTooManyRequests{}
}

/*
WorkflowActivitiesCombinedTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type WorkflowActivitiesCombinedTooManyRequests struct {

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

// IsSuccess returns true when this workflow activities combined too many requests response has a 2xx status code
func (o *WorkflowActivitiesCombinedTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow activities combined too many requests response has a 3xx status code
func (o *WorkflowActivitiesCombinedTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow activities combined too many requests response has a 4xx status code
func (o *WorkflowActivitiesCombinedTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow activities combined too many requests response has a 5xx status code
func (o *WorkflowActivitiesCombinedTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow activities combined too many requests response a status code equal to that given
func (o *WorkflowActivitiesCombinedTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the workflow activities combined too many requests response
func (o *WorkflowActivitiesCombinedTooManyRequests) Code() int {
	return 429
}

func (o *WorkflowActivitiesCombinedTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedTooManyRequests  %+v", 429, o.Payload)
}

func (o *WorkflowActivitiesCombinedTooManyRequests) String() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedTooManyRequests  %+v", 429, o.Payload)
}

func (o *WorkflowActivitiesCombinedTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *WorkflowActivitiesCombinedTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewWorkflowActivitiesCombinedInternalServerError creates a WorkflowActivitiesCombinedInternalServerError with default headers values
func NewWorkflowActivitiesCombinedInternalServerError() *WorkflowActivitiesCombinedInternalServerError {
	return &WorkflowActivitiesCombinedInternalServerError{}
}

/*
WorkflowActivitiesCombinedInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type WorkflowActivitiesCombinedInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ActivitiesLegacyActivityExternalResponse
}

// IsSuccess returns true when this workflow activities combined internal server error response has a 2xx status code
func (o *WorkflowActivitiesCombinedInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow activities combined internal server error response has a 3xx status code
func (o *WorkflowActivitiesCombinedInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow activities combined internal server error response has a 4xx status code
func (o *WorkflowActivitiesCombinedInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this workflow activities combined internal server error response has a 5xx status code
func (o *WorkflowActivitiesCombinedInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this workflow activities combined internal server error response a status code equal to that given
func (o *WorkflowActivitiesCombinedInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the workflow activities combined internal server error response
func (o *WorkflowActivitiesCombinedInternalServerError) Code() int {
	return 500
}

func (o *WorkflowActivitiesCombinedInternalServerError) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedInternalServerError  %+v", 500, o.Payload)
}

func (o *WorkflowActivitiesCombinedInternalServerError) String() string {
	return fmt.Sprintf("[GET /workflows/combined/activities/v1][%d] workflowActivitiesCombinedInternalServerError  %+v", 500, o.Payload)
}

func (o *WorkflowActivitiesCombinedInternalServerError) GetPayload() *models.ActivitiesLegacyActivityExternalResponse {
	return o.Payload
}

func (o *WorkflowActivitiesCombinedInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ActivitiesLegacyActivityExternalResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
