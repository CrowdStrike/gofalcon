// Code generated by go-swagger; DO NOT EDIT.

package real_time_response

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

// BatchActiveResponderCmdReader is a Reader for the BatchActiveResponderCmd structure.
type BatchActiveResponderCmdReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BatchActiveResponderCmdReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewBatchActiveResponderCmdCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewBatchActiveResponderCmdBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewBatchActiveResponderCmdForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewBatchActiveResponderCmdTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewBatchActiveResponderCmdInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /real-time-response/combined/batch-active-responder-command/v1] BatchActiveResponderCmd", response, response.Code())
	}
}

// NewBatchActiveResponderCmdCreated creates a BatchActiveResponderCmdCreated with default headers values
func NewBatchActiveResponderCmdCreated() *BatchActiveResponderCmdCreated {
	return &BatchActiveResponderCmdCreated{}
}

/* BatchActiveResponderCmdCreated describes a response with status code 201, with default header values.

Created
*/
type BatchActiveResponderCmdCreated struct {

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

// IsSuccess returns true when this batch active responder cmd created response has a 2xx status code
func (o *BatchActiveResponderCmdCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this batch active responder cmd created response has a 3xx status code
func (o *BatchActiveResponderCmdCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch active responder cmd created response has a 4xx status code
func (o *BatchActiveResponderCmdCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this batch active responder cmd created response has a 5xx status code
func (o *BatchActiveResponderCmdCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this batch active responder cmd created response a status code equal to that given
func (o *BatchActiveResponderCmdCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the batch active responder cmd created response
func (o *BatchActiveResponderCmdCreated) Code() int {
	return 201
}

func (o *BatchActiveResponderCmdCreated) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdCreated  %+v", 201, o.Payload)
}

func (o *BatchActiveResponderCmdCreated) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdCreated  %+v", 201, o.Payload)
}

func (o *BatchActiveResponderCmdCreated) GetPayload() *models.DomainMultiCommandExecuteResponseWrapper {
	return o.Payload
}

func (o *BatchActiveResponderCmdCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewBatchActiveResponderCmdBadRequest creates a BatchActiveResponderCmdBadRequest with default headers values
func NewBatchActiveResponderCmdBadRequest() *BatchActiveResponderCmdBadRequest {
	return &BatchActiveResponderCmdBadRequest{}
}

/* BatchActiveResponderCmdBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type BatchActiveResponderCmdBadRequest struct {

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

// IsSuccess returns true when this batch active responder cmd bad request response has a 2xx status code
func (o *BatchActiveResponderCmdBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch active responder cmd bad request response has a 3xx status code
func (o *BatchActiveResponderCmdBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch active responder cmd bad request response has a 4xx status code
func (o *BatchActiveResponderCmdBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this batch active responder cmd bad request response has a 5xx status code
func (o *BatchActiveResponderCmdBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this batch active responder cmd bad request response a status code equal to that given
func (o *BatchActiveResponderCmdBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the batch active responder cmd bad request response
func (o *BatchActiveResponderCmdBadRequest) Code() int {
	return 400
}

func (o *BatchActiveResponderCmdBadRequest) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdBadRequest  %+v", 400, o.Payload)
}

func (o *BatchActiveResponderCmdBadRequest) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdBadRequest  %+v", 400, o.Payload)
}

func (o *BatchActiveResponderCmdBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *BatchActiveResponderCmdBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewBatchActiveResponderCmdForbidden creates a BatchActiveResponderCmdForbidden with default headers values
func NewBatchActiveResponderCmdForbidden() *BatchActiveResponderCmdForbidden {
	return &BatchActiveResponderCmdForbidden{}
}

/* BatchActiveResponderCmdForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type BatchActiveResponderCmdForbidden struct {

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

// IsSuccess returns true when this batch active responder cmd forbidden response has a 2xx status code
func (o *BatchActiveResponderCmdForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch active responder cmd forbidden response has a 3xx status code
func (o *BatchActiveResponderCmdForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch active responder cmd forbidden response has a 4xx status code
func (o *BatchActiveResponderCmdForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this batch active responder cmd forbidden response has a 5xx status code
func (o *BatchActiveResponderCmdForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this batch active responder cmd forbidden response a status code equal to that given
func (o *BatchActiveResponderCmdForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the batch active responder cmd forbidden response
func (o *BatchActiveResponderCmdForbidden) Code() int {
	return 403
}

func (o *BatchActiveResponderCmdForbidden) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdForbidden  %+v", 403, o.Payload)
}

func (o *BatchActiveResponderCmdForbidden) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdForbidden  %+v", 403, o.Payload)
}

func (o *BatchActiveResponderCmdForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *BatchActiveResponderCmdForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewBatchActiveResponderCmdTooManyRequests creates a BatchActiveResponderCmdTooManyRequests with default headers values
func NewBatchActiveResponderCmdTooManyRequests() *BatchActiveResponderCmdTooManyRequests {
	return &BatchActiveResponderCmdTooManyRequests{}
}

/* BatchActiveResponderCmdTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type BatchActiveResponderCmdTooManyRequests struct {

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

// IsSuccess returns true when this batch active responder cmd too many requests response has a 2xx status code
func (o *BatchActiveResponderCmdTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch active responder cmd too many requests response has a 3xx status code
func (o *BatchActiveResponderCmdTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch active responder cmd too many requests response has a 4xx status code
func (o *BatchActiveResponderCmdTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this batch active responder cmd too many requests response has a 5xx status code
func (o *BatchActiveResponderCmdTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this batch active responder cmd too many requests response a status code equal to that given
func (o *BatchActiveResponderCmdTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the batch active responder cmd too many requests response
func (o *BatchActiveResponderCmdTooManyRequests) Code() int {
	return 429
}

func (o *BatchActiveResponderCmdTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdTooManyRequests  %+v", 429, o.Payload)
}

func (o *BatchActiveResponderCmdTooManyRequests) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdTooManyRequests  %+v", 429, o.Payload)
}

func (o *BatchActiveResponderCmdTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *BatchActiveResponderCmdTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewBatchActiveResponderCmdInternalServerError creates a BatchActiveResponderCmdInternalServerError with default headers values
func NewBatchActiveResponderCmdInternalServerError() *BatchActiveResponderCmdInternalServerError {
	return &BatchActiveResponderCmdInternalServerError{}
}

/* BatchActiveResponderCmdInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type BatchActiveResponderCmdInternalServerError struct {

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

// IsSuccess returns true when this batch active responder cmd internal server error response has a 2xx status code
func (o *BatchActiveResponderCmdInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this batch active responder cmd internal server error response has a 3xx status code
func (o *BatchActiveResponderCmdInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch active responder cmd internal server error response has a 4xx status code
func (o *BatchActiveResponderCmdInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this batch active responder cmd internal server error response has a 5xx status code
func (o *BatchActiveResponderCmdInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this batch active responder cmd internal server error response a status code equal to that given
func (o *BatchActiveResponderCmdInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the batch active responder cmd internal server error response
func (o *BatchActiveResponderCmdInternalServerError) Code() int {
	return 500
}

func (o *BatchActiveResponderCmdInternalServerError) Error() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdInternalServerError  %+v", 500, o.Payload)
}

func (o *BatchActiveResponderCmdInternalServerError) String() string {
	return fmt.Sprintf("[POST /real-time-response/combined/batch-active-responder-command/v1][%d] batchActiveResponderCmdInternalServerError  %+v", 500, o.Payload)
}

func (o *BatchActiveResponderCmdInternalServerError) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *BatchActiveResponderCmdInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
