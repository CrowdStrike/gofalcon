// Code generated by go-swagger; DO NOT EDIT.

package real_time_response_admin

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

// BatchAdminCmdReader is a Reader for the BatchAdminCmd structure.
type BatchAdminCmdReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BatchAdminCmdReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewBatchAdminCmdCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewBatchAdminCmdBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewBatchAdminCmdForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewBatchAdminCmdTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewBatchAdminCmdInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /real-time-response/combined/batch-admin-command/v1] BatchAdminCmd", response, response.Code())
	}
}

// NewBatchAdminCmdCreated creates a BatchAdminCmdCreated with default headers values
func NewBatchAdminCmdCreated() *BatchAdminCmdCreated {
	return &BatchAdminCmdCreated{}
}

/*
BatchAdminCmdCreated describes a response with status code 201, with default header values.

Created
*/
type BatchAdminCmdCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainMultiCommandExecuteResponseWrapper
}

// IsSuccess returns true when this batch admin cmd created response has a 2xx status code
func (o *BatchAdminCmdCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this batch admin cmd created response has a 3xx status code
func (o *BatchAdminCmdCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch admin cmd created response has a 4xx status code
func (o *BatchAdminCmdCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this batch admin cmd created response has a 5xx status code
func (o *BatchAdminCmdCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this batch admin cmd created response a status code equal to that given
func (o *BatchAdminCmdCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the batch admin cmd created response
func (o *BatchAdminCmdCreated) Code() int {
	return 201
}

func (o *BatchAdminCmdCreated) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdCreated  %+v", 201, o.Payload)
}

func (o *BatchAdminCmdCreated) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdCreated  %+v", 201, o.Payload)
}

func (o *BatchAdminCmdCreated) GetPayload() *models.DomainMultiCommandExecuteResponseWrapper {
	return o.Payload
}

func (o *BatchAdminCmdCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainMultiCommandExecuteResponseWrapper)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBatchAdminCmdBadRequest creates a BatchAdminCmdBadRequest with default headers values
func NewBatchAdminCmdBadRequest() *BatchAdminCmdBadRequest {
	return &BatchAdminCmdBadRequest{}
}

/*
BatchAdminCmdBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type BatchAdminCmdBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIError
}

// IsSuccess returns true when this batch admin cmd bad request response has a 2xx status code
func (o *BatchAdminCmdBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch admin cmd bad request response has a 3xx status code
func (o *BatchAdminCmdBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch admin cmd bad request response has a 4xx status code
func (o *BatchAdminCmdBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this batch admin cmd bad request response has a 5xx status code
func (o *BatchAdminCmdBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this batch admin cmd bad request response a status code equal to that given
func (o *BatchAdminCmdBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the batch admin cmd bad request response
func (o *BatchAdminCmdBadRequest) Code() int {
	return 400
}

func (o *BatchAdminCmdBadRequest) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdBadRequest  %+v", 400, o.Payload)
}

func (o *BatchAdminCmdBadRequest) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdBadRequest  %+v", 400, o.Payload)
}

func (o *BatchAdminCmdBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *BatchAdminCmdBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBatchAdminCmdForbidden creates a BatchAdminCmdForbidden with default headers values
func NewBatchAdminCmdForbidden() *BatchAdminCmdForbidden {
	return &BatchAdminCmdForbidden{}
}

/*
BatchAdminCmdForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type BatchAdminCmdForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this batch admin cmd forbidden response has a 2xx status code
func (o *BatchAdminCmdForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch admin cmd forbidden response has a 3xx status code
func (o *BatchAdminCmdForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch admin cmd forbidden response has a 4xx status code
func (o *BatchAdminCmdForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this batch admin cmd forbidden response has a 5xx status code
func (o *BatchAdminCmdForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this batch admin cmd forbidden response a status code equal to that given
func (o *BatchAdminCmdForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the batch admin cmd forbidden response
func (o *BatchAdminCmdForbidden) Code() int {
	return 403
}

func (o *BatchAdminCmdForbidden) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdForbidden  %+v", 403, o.Payload)
}

func (o *BatchAdminCmdForbidden) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdForbidden  %+v", 403, o.Payload)
}

func (o *BatchAdminCmdForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *BatchAdminCmdForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBatchAdminCmdTooManyRequests creates a BatchAdminCmdTooManyRequests with default headers values
func NewBatchAdminCmdTooManyRequests() *BatchAdminCmdTooManyRequests {
	return &BatchAdminCmdTooManyRequests{}
}

/*
BatchAdminCmdTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type BatchAdminCmdTooManyRequests struct {

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

// IsSuccess returns true when this batch admin cmd too many requests response has a 2xx status code
func (o *BatchAdminCmdTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch admin cmd too many requests response has a 3xx status code
func (o *BatchAdminCmdTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch admin cmd too many requests response has a 4xx status code
func (o *BatchAdminCmdTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this batch admin cmd too many requests response has a 5xx status code
func (o *BatchAdminCmdTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this batch admin cmd too many requests response a status code equal to that given
func (o *BatchAdminCmdTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the batch admin cmd too many requests response
func (o *BatchAdminCmdTooManyRequests) Code() int {
	return 429
}

func (o *BatchAdminCmdTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdTooManyRequests  %+v", 429, o.Payload)
}

func (o *BatchAdminCmdTooManyRequests) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdTooManyRequests  %+v", 429, o.Payload)
}

func (o *BatchAdminCmdTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *BatchAdminCmdTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewBatchAdminCmdInternalServerError creates a BatchAdminCmdInternalServerError with default headers values
func NewBatchAdminCmdInternalServerError() *BatchAdminCmdInternalServerError {
	return &BatchAdminCmdInternalServerError{}
}

/*
BatchAdminCmdInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type BatchAdminCmdInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIError
}

// IsSuccess returns true when this batch admin cmd internal server error response has a 2xx status code
func (o *BatchAdminCmdInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch admin cmd internal server error response has a 3xx status code
func (o *BatchAdminCmdInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch admin cmd internal server error response has a 4xx status code
func (o *BatchAdminCmdInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this batch admin cmd internal server error response has a 5xx status code
func (o *BatchAdminCmdInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this batch admin cmd internal server error response a status code equal to that given
func (o *BatchAdminCmdInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the batch admin cmd internal server error response
func (o *BatchAdminCmdInternalServerError) Code() int {
	return 500
}

func (o *BatchAdminCmdInternalServerError) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdInternalServerError  %+v", 500, o.Payload)
}

func (o *BatchAdminCmdInternalServerError) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-admin-command/v1][%d] batchAdminCmdInternalServerError  %+v", 500, o.Payload)
}

func (o *BatchAdminCmdInternalServerError) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *BatchAdminCmdInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
