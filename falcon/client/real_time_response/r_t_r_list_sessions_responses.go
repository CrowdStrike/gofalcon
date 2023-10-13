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

// RTRListSessionsReader is a Reader for the RTRListSessions structure.
type RTRListSessionsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RTRListSessionsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRTRListSessionsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRTRListSessionsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRTRListSessionsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRTRListSessionsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRTRListSessionsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /real-time-response/entities/sessions/GET/v1] RTR-ListSessions", response, response.Code())
	}
}

// NewRTRListSessionsOK creates a RTRListSessionsOK with default headers values
func NewRTRListSessionsOK() *RTRListSessionsOK {
	return &RTRListSessionsOK{}
}

/* RTRListSessionsOK describes a response with status code 200, with default header values.

OK
*/
type RTRListSessionsOK struct {

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

// IsSuccess returns true when this r t r list sessions o k response has a 2xx status code
func (o *RTRListSessionsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this r t r list sessions o k response has a 3xx status code
func (o *RTRListSessionsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list sessions o k response has a 4xx status code
func (o *RTRListSessionsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r list sessions o k response has a 5xx status code
func (o *RTRListSessionsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list sessions o k response a status code equal to that given
func (o *RTRListSessionsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the r t r list sessions o k response
func (o *RTRListSessionsOK) Code() int {
	return 200
}

func (o *RTRListSessionsOK) Error() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsOK  %+v", 200, o.Payload)
}

func (o *RTRListSessionsOK) String() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsOK  %+v", 200, o.Payload)
}

func (o *RTRListSessionsOK) GetPayload() *models.DomainSessionResponseWrapper {
	return o.Payload
}

func (o *RTRListSessionsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRListSessionsBadRequest creates a RTRListSessionsBadRequest with default headers values
func NewRTRListSessionsBadRequest() *RTRListSessionsBadRequest {
	return &RTRListSessionsBadRequest{}
}

/* RTRListSessionsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RTRListSessionsBadRequest struct {

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

// IsSuccess returns true when this r t r list sessions bad request response has a 2xx status code
func (o *RTRListSessionsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list sessions bad request response has a 3xx status code
func (o *RTRListSessionsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list sessions bad request response has a 4xx status code
func (o *RTRListSessionsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list sessions bad request response has a 5xx status code
func (o *RTRListSessionsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list sessions bad request response a status code equal to that given
func (o *RTRListSessionsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the r t r list sessions bad request response
func (o *RTRListSessionsBadRequest) Code() int {
	return 400
}

func (o *RTRListSessionsBadRequest) Error() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRListSessionsBadRequest) String() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRListSessionsBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRListSessionsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRListSessionsForbidden creates a RTRListSessionsForbidden with default headers values
func NewRTRListSessionsForbidden() *RTRListSessionsForbidden {
	return &RTRListSessionsForbidden{}
}

/* RTRListSessionsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RTRListSessionsForbidden struct {

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

// IsSuccess returns true when this r t r list sessions forbidden response has a 2xx status code
func (o *RTRListSessionsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list sessions forbidden response has a 3xx status code
func (o *RTRListSessionsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list sessions forbidden response has a 4xx status code
func (o *RTRListSessionsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list sessions forbidden response has a 5xx status code
func (o *RTRListSessionsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list sessions forbidden response a status code equal to that given
func (o *RTRListSessionsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the r t r list sessions forbidden response
func (o *RTRListSessionsForbidden) Code() int {
	return 403
}

func (o *RTRListSessionsForbidden) Error() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsForbidden  %+v", 403, o.Payload)
}

func (o *RTRListSessionsForbidden) String() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsForbidden  %+v", 403, o.Payload)
}

func (o *RTRListSessionsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRListSessionsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRListSessionsNotFound creates a RTRListSessionsNotFound with default headers values
func NewRTRListSessionsNotFound() *RTRListSessionsNotFound {
	return &RTRListSessionsNotFound{}
}

/* RTRListSessionsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type RTRListSessionsNotFound struct {

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

// IsSuccess returns true when this r t r list sessions not found response has a 2xx status code
func (o *RTRListSessionsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list sessions not found response has a 3xx status code
func (o *RTRListSessionsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list sessions not found response has a 4xx status code
func (o *RTRListSessionsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list sessions not found response has a 5xx status code
func (o *RTRListSessionsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list sessions not found response a status code equal to that given
func (o *RTRListSessionsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the r t r list sessions not found response
func (o *RTRListSessionsNotFound) Code() int {
	return 404
}

func (o *RTRListSessionsNotFound) Error() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsNotFound  %+v", 404, o.Payload)
}

func (o *RTRListSessionsNotFound) String() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsNotFound  %+v", 404, o.Payload)
}

func (o *RTRListSessionsNotFound) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRListSessionsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRListSessionsTooManyRequests creates a RTRListSessionsTooManyRequests with default headers values
func NewRTRListSessionsTooManyRequests() *RTRListSessionsTooManyRequests {
	return &RTRListSessionsTooManyRequests{}
}

/* RTRListSessionsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RTRListSessionsTooManyRequests struct {

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

// IsSuccess returns true when this r t r list sessions too many requests response has a 2xx status code
func (o *RTRListSessionsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list sessions too many requests response has a 3xx status code
func (o *RTRListSessionsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list sessions too many requests response has a 4xx status code
func (o *RTRListSessionsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list sessions too many requests response has a 5xx status code
func (o *RTRListSessionsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list sessions too many requests response a status code equal to that given
func (o *RTRListSessionsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the r t r list sessions too many requests response
func (o *RTRListSessionsTooManyRequests) Code() int {
	return 429
}

func (o *RTRListSessionsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRListSessionsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /real-time-response/entities/sessions/GET/v1][%d] rTRListSessionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRListSessionsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRListSessionsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
