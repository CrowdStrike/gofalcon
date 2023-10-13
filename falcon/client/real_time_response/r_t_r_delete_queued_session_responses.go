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

// RTRDeleteQueuedSessionReader is a Reader for the RTRDeleteQueuedSession structure.
type RTRDeleteQueuedSessionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RTRDeleteQueuedSessionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRTRDeleteQueuedSessionNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRTRDeleteQueuedSessionBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRTRDeleteQueuedSessionUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRTRDeleteQueuedSessionForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRTRDeleteQueuedSessionTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /real-time-response/entities/queued-sessions/command/v1] RTR-DeleteQueuedSession", response, response.Code())
	}
}

// NewRTRDeleteQueuedSessionNoContent creates a RTRDeleteQueuedSessionNoContent with default headers values
func NewRTRDeleteQueuedSessionNoContent() *RTRDeleteQueuedSessionNoContent {
	return &RTRDeleteQueuedSessionNoContent{}
}

/* RTRDeleteQueuedSessionNoContent describes a response with status code 204, with default header values.

No Content
*/
type RTRDeleteQueuedSessionNoContent struct {

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

// IsSuccess returns true when this r t r delete queued session no content response has a 2xx status code
func (o *RTRDeleteQueuedSessionNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this r t r delete queued session no content response has a 3xx status code
func (o *RTRDeleteQueuedSessionNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r delete queued session no content response has a 4xx status code
func (o *RTRDeleteQueuedSessionNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r delete queued session no content response has a 5xx status code
func (o *RTRDeleteQueuedSessionNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r delete queued session no content response a status code equal to that given
func (o *RTRDeleteQueuedSessionNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the r t r delete queued session no content response
func (o *RTRDeleteQueuedSessionNoContent) Code() int {
	return 204
}

func (o *RTRDeleteQueuedSessionNoContent) Error() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionNoContent  %+v", 204, o.Payload)
}

func (o *RTRDeleteQueuedSessionNoContent) String() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionNoContent  %+v", 204, o.Payload)
}

func (o *RTRDeleteQueuedSessionNoContent) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRDeleteQueuedSessionNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRDeleteQueuedSessionBadRequest creates a RTRDeleteQueuedSessionBadRequest with default headers values
func NewRTRDeleteQueuedSessionBadRequest() *RTRDeleteQueuedSessionBadRequest {
	return &RTRDeleteQueuedSessionBadRequest{}
}

/* RTRDeleteQueuedSessionBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RTRDeleteQueuedSessionBadRequest struct {

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

// IsSuccess returns true when this r t r delete queued session bad request response has a 2xx status code
func (o *RTRDeleteQueuedSessionBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r delete queued session bad request response has a 3xx status code
func (o *RTRDeleteQueuedSessionBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r delete queued session bad request response has a 4xx status code
func (o *RTRDeleteQueuedSessionBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r delete queued session bad request response has a 5xx status code
func (o *RTRDeleteQueuedSessionBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r delete queued session bad request response a status code equal to that given
func (o *RTRDeleteQueuedSessionBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the r t r delete queued session bad request response
func (o *RTRDeleteQueuedSessionBadRequest) Code() int {
	return 400
}

func (o *RTRDeleteQueuedSessionBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionBadRequest  %+v", 400, o.Payload)
}

func (o *RTRDeleteQueuedSessionBadRequest) String() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionBadRequest  %+v", 400, o.Payload)
}

func (o *RTRDeleteQueuedSessionBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRDeleteQueuedSessionBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRDeleteQueuedSessionUnauthorized creates a RTRDeleteQueuedSessionUnauthorized with default headers values
func NewRTRDeleteQueuedSessionUnauthorized() *RTRDeleteQueuedSessionUnauthorized {
	return &RTRDeleteQueuedSessionUnauthorized{}
}

/* RTRDeleteQueuedSessionUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RTRDeleteQueuedSessionUnauthorized struct {

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

// IsSuccess returns true when this r t r delete queued session unauthorized response has a 2xx status code
func (o *RTRDeleteQueuedSessionUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r delete queued session unauthorized response has a 3xx status code
func (o *RTRDeleteQueuedSessionUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r delete queued session unauthorized response has a 4xx status code
func (o *RTRDeleteQueuedSessionUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r delete queued session unauthorized response has a 5xx status code
func (o *RTRDeleteQueuedSessionUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r delete queued session unauthorized response a status code equal to that given
func (o *RTRDeleteQueuedSessionUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the r t r delete queued session unauthorized response
func (o *RTRDeleteQueuedSessionUnauthorized) Code() int {
	return 401
}

func (o *RTRDeleteQueuedSessionUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionUnauthorized  %+v", 401, o.Payload)
}

func (o *RTRDeleteQueuedSessionUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionUnauthorized  %+v", 401, o.Payload)
}

func (o *RTRDeleteQueuedSessionUnauthorized) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRDeleteQueuedSessionUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRDeleteQueuedSessionForbidden creates a RTRDeleteQueuedSessionForbidden with default headers values
func NewRTRDeleteQueuedSessionForbidden() *RTRDeleteQueuedSessionForbidden {
	return &RTRDeleteQueuedSessionForbidden{}
}

/* RTRDeleteQueuedSessionForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RTRDeleteQueuedSessionForbidden struct {

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

// IsSuccess returns true when this r t r delete queued session forbidden response has a 2xx status code
func (o *RTRDeleteQueuedSessionForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r delete queued session forbidden response has a 3xx status code
func (o *RTRDeleteQueuedSessionForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r delete queued session forbidden response has a 4xx status code
func (o *RTRDeleteQueuedSessionForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r delete queued session forbidden response has a 5xx status code
func (o *RTRDeleteQueuedSessionForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r delete queued session forbidden response a status code equal to that given
func (o *RTRDeleteQueuedSessionForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the r t r delete queued session forbidden response
func (o *RTRDeleteQueuedSessionForbidden) Code() int {
	return 403
}

func (o *RTRDeleteQueuedSessionForbidden) Error() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionForbidden  %+v", 403, o.Payload)
}

func (o *RTRDeleteQueuedSessionForbidden) String() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionForbidden  %+v", 403, o.Payload)
}

func (o *RTRDeleteQueuedSessionForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRDeleteQueuedSessionForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRDeleteQueuedSessionTooManyRequests creates a RTRDeleteQueuedSessionTooManyRequests with default headers values
func NewRTRDeleteQueuedSessionTooManyRequests() *RTRDeleteQueuedSessionTooManyRequests {
	return &RTRDeleteQueuedSessionTooManyRequests{}
}

/* RTRDeleteQueuedSessionTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RTRDeleteQueuedSessionTooManyRequests struct {

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

// IsSuccess returns true when this r t r delete queued session too many requests response has a 2xx status code
func (o *RTRDeleteQueuedSessionTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r delete queued session too many requests response has a 3xx status code
func (o *RTRDeleteQueuedSessionTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r delete queued session too many requests response has a 4xx status code
func (o *RTRDeleteQueuedSessionTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r delete queued session too many requests response has a 5xx status code
func (o *RTRDeleteQueuedSessionTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r delete queued session too many requests response a status code equal to that given
func (o *RTRDeleteQueuedSessionTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the r t r delete queued session too many requests response
func (o *RTRDeleteQueuedSessionTooManyRequests) Code() int {
	return 429
}

func (o *RTRDeleteQueuedSessionTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRDeleteQueuedSessionTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /real-time-response/entities/queued-sessions/command/v1][%d] rTRDeleteQueuedSessionTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRDeleteQueuedSessionTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRDeleteQueuedSessionTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
