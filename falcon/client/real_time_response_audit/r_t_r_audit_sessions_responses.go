// Code generated by go-swagger; DO NOT EDIT.

package real_time_response_audit

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

// RTRAuditSessionsReader is a Reader for the RTRAuditSessions structure.
type RTRAuditSessionsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RTRAuditSessionsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRTRAuditSessionsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRTRAuditSessionsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRTRAuditSessionsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRTRAuditSessionsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRTRAuditSessionsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /real-time-response-audit/combined/sessions/v1] RTRAuditSessions", response, response.Code())
	}
}

// NewRTRAuditSessionsOK creates a RTRAuditSessionsOK with default headers values
func NewRTRAuditSessionsOK() *RTRAuditSessionsOK {
	return &RTRAuditSessionsOK{}
}

/* RTRAuditSessionsOK describes a response with status code 200, with default header values.

OK
*/
type RTRAuditSessionsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainSessionResponseWrapper
}

// IsSuccess returns true when this r t r audit sessions o k response has a 2xx status code
func (o *RTRAuditSessionsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this r t r audit sessions o k response has a 3xx status code
func (o *RTRAuditSessionsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r audit sessions o k response has a 4xx status code
func (o *RTRAuditSessionsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r audit sessions o k response has a 5xx status code
func (o *RTRAuditSessionsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r audit sessions o k response a status code equal to that given
func (o *RTRAuditSessionsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the r t r audit sessions o k response
func (o *RTRAuditSessionsOK) Code() int {
	return 200
}

func (o *RTRAuditSessionsOK) Error() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsOK  %+v", 200, o.Payload)
}

func (o *RTRAuditSessionsOK) String() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsOK  %+v", 200, o.Payload)
}

func (o *RTRAuditSessionsOK) GetPayload() *models.DomainSessionResponseWrapper {
	return o.Payload
}

func (o *RTRAuditSessionsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainSessionResponseWrapper)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRTRAuditSessionsBadRequest creates a RTRAuditSessionsBadRequest with default headers values
func NewRTRAuditSessionsBadRequest() *RTRAuditSessionsBadRequest {
	return &RTRAuditSessionsBadRequest{}
}

/* RTRAuditSessionsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RTRAuditSessionsBadRequest struct {

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

// IsSuccess returns true when this r t r audit sessions bad request response has a 2xx status code
func (o *RTRAuditSessionsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r audit sessions bad request response has a 3xx status code
func (o *RTRAuditSessionsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r audit sessions bad request response has a 4xx status code
func (o *RTRAuditSessionsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r audit sessions bad request response has a 5xx status code
func (o *RTRAuditSessionsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r audit sessions bad request response a status code equal to that given
func (o *RTRAuditSessionsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the r t r audit sessions bad request response
func (o *RTRAuditSessionsBadRequest) Code() int {
	return 400
}

func (o *RTRAuditSessionsBadRequest) Error() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRAuditSessionsBadRequest) String() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRAuditSessionsBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRAuditSessionsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRAuditSessionsForbidden creates a RTRAuditSessionsForbidden with default headers values
func NewRTRAuditSessionsForbidden() *RTRAuditSessionsForbidden {
	return &RTRAuditSessionsForbidden{}
}

/* RTRAuditSessionsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RTRAuditSessionsForbidden struct {

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

// IsSuccess returns true when this r t r audit sessions forbidden response has a 2xx status code
func (o *RTRAuditSessionsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r audit sessions forbidden response has a 3xx status code
func (o *RTRAuditSessionsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r audit sessions forbidden response has a 4xx status code
func (o *RTRAuditSessionsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r audit sessions forbidden response has a 5xx status code
func (o *RTRAuditSessionsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r audit sessions forbidden response a status code equal to that given
func (o *RTRAuditSessionsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the r t r audit sessions forbidden response
func (o *RTRAuditSessionsForbidden) Code() int {
	return 403
}

func (o *RTRAuditSessionsForbidden) Error() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsForbidden  %+v", 403, o.Payload)
}

func (o *RTRAuditSessionsForbidden) String() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsForbidden  %+v", 403, o.Payload)
}

func (o *RTRAuditSessionsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRAuditSessionsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRAuditSessionsNotFound creates a RTRAuditSessionsNotFound with default headers values
func NewRTRAuditSessionsNotFound() *RTRAuditSessionsNotFound {
	return &RTRAuditSessionsNotFound{}
}

/* RTRAuditSessionsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type RTRAuditSessionsNotFound struct {

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

// IsSuccess returns true when this r t r audit sessions not found response has a 2xx status code
func (o *RTRAuditSessionsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r audit sessions not found response has a 3xx status code
func (o *RTRAuditSessionsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r audit sessions not found response has a 4xx status code
func (o *RTRAuditSessionsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r audit sessions not found response has a 5xx status code
func (o *RTRAuditSessionsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r audit sessions not found response a status code equal to that given
func (o *RTRAuditSessionsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the r t r audit sessions not found response
func (o *RTRAuditSessionsNotFound) Code() int {
	return 404
}

func (o *RTRAuditSessionsNotFound) Error() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsNotFound  %+v", 404, o.Payload)
}

func (o *RTRAuditSessionsNotFound) String() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsNotFound  %+v", 404, o.Payload)
}

func (o *RTRAuditSessionsNotFound) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRAuditSessionsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRAuditSessionsTooManyRequests creates a RTRAuditSessionsTooManyRequests with default headers values
func NewRTRAuditSessionsTooManyRequests() *RTRAuditSessionsTooManyRequests {
	return &RTRAuditSessionsTooManyRequests{}
}

/* RTRAuditSessionsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RTRAuditSessionsTooManyRequests struct {

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

// IsSuccess returns true when this r t r audit sessions too many requests response has a 2xx status code
func (o *RTRAuditSessionsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r audit sessions too many requests response has a 3xx status code
func (o *RTRAuditSessionsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r audit sessions too many requests response has a 4xx status code
func (o *RTRAuditSessionsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r audit sessions too many requests response has a 5xx status code
func (o *RTRAuditSessionsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r audit sessions too many requests response a status code equal to that given
func (o *RTRAuditSessionsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the r t r audit sessions too many requests response
func (o *RTRAuditSessionsTooManyRequests) Code() int {
	return 429
}

func (o *RTRAuditSessionsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRAuditSessionsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /real-time-response-audit/combined/sessions/v1][%d] rTRAuditSessionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRAuditSessionsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRAuditSessionsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
