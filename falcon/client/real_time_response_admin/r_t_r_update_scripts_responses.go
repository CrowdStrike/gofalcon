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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// RTRUpdateScriptsReader is a Reader for the RTRUpdateScripts structure.
type RTRUpdateScriptsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RTRUpdateScriptsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRTRUpdateScriptsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRTRUpdateScriptsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRTRUpdateScriptsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRTRUpdateScriptsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /real-time-response/entities/scripts/v1] RTR-UpdateScripts", response, response.Code())
	}
}

// NewRTRUpdateScriptsOK creates a RTRUpdateScriptsOK with default headers values
func NewRTRUpdateScriptsOK() *RTRUpdateScriptsOK {
	return &RTRUpdateScriptsOK{}
}

/* RTRUpdateScriptsOK describes a response with status code 200, with default header values.

OK
*/
type RTRUpdateScriptsOK struct {

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

// IsSuccess returns true when this r t r update scripts o k response has a 2xx status code
func (o *RTRUpdateScriptsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this r t r update scripts o k response has a 3xx status code
func (o *RTRUpdateScriptsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r update scripts o k response has a 4xx status code
func (o *RTRUpdateScriptsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r update scripts o k response has a 5xx status code
func (o *RTRUpdateScriptsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r update scripts o k response a status code equal to that given
func (o *RTRUpdateScriptsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the r t r update scripts o k response
func (o *RTRUpdateScriptsOK) Code() int {
	return 200
}

func (o *RTRUpdateScriptsOK) Error() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsOK  %+v", 200, o.Payload)
}

func (o *RTRUpdateScriptsOK) String() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsOK  %+v", 200, o.Payload)
}

func (o *RTRUpdateScriptsOK) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRUpdateScriptsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRUpdateScriptsBadRequest creates a RTRUpdateScriptsBadRequest with default headers values
func NewRTRUpdateScriptsBadRequest() *RTRUpdateScriptsBadRequest {
	return &RTRUpdateScriptsBadRequest{}
}

/* RTRUpdateScriptsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RTRUpdateScriptsBadRequest struct {

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

// IsSuccess returns true when this r t r update scripts bad request response has a 2xx status code
func (o *RTRUpdateScriptsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r update scripts bad request response has a 3xx status code
func (o *RTRUpdateScriptsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r update scripts bad request response has a 4xx status code
func (o *RTRUpdateScriptsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r update scripts bad request response has a 5xx status code
func (o *RTRUpdateScriptsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r update scripts bad request response a status code equal to that given
func (o *RTRUpdateScriptsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the r t r update scripts bad request response
func (o *RTRUpdateScriptsBadRequest) Code() int {
	return 400
}

func (o *RTRUpdateScriptsBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRUpdateScriptsBadRequest) String() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRUpdateScriptsBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRUpdateScriptsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRUpdateScriptsForbidden creates a RTRUpdateScriptsForbidden with default headers values
func NewRTRUpdateScriptsForbidden() *RTRUpdateScriptsForbidden {
	return &RTRUpdateScriptsForbidden{}
}

/* RTRUpdateScriptsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RTRUpdateScriptsForbidden struct {

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

// IsSuccess returns true when this r t r update scripts forbidden response has a 2xx status code
func (o *RTRUpdateScriptsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r update scripts forbidden response has a 3xx status code
func (o *RTRUpdateScriptsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r update scripts forbidden response has a 4xx status code
func (o *RTRUpdateScriptsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r update scripts forbidden response has a 5xx status code
func (o *RTRUpdateScriptsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r update scripts forbidden response a status code equal to that given
func (o *RTRUpdateScriptsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the r t r update scripts forbidden response
func (o *RTRUpdateScriptsForbidden) Code() int {
	return 403
}

func (o *RTRUpdateScriptsForbidden) Error() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsForbidden  %+v", 403, o.Payload)
}

func (o *RTRUpdateScriptsForbidden) String() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsForbidden  %+v", 403, o.Payload)
}

func (o *RTRUpdateScriptsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRUpdateScriptsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRUpdateScriptsTooManyRequests creates a RTRUpdateScriptsTooManyRequests with default headers values
func NewRTRUpdateScriptsTooManyRequests() *RTRUpdateScriptsTooManyRequests {
	return &RTRUpdateScriptsTooManyRequests{}
}

/* RTRUpdateScriptsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RTRUpdateScriptsTooManyRequests struct {

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

// IsSuccess returns true when this r t r update scripts too many requests response has a 2xx status code
func (o *RTRUpdateScriptsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r update scripts too many requests response has a 3xx status code
func (o *RTRUpdateScriptsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r update scripts too many requests response has a 4xx status code
func (o *RTRUpdateScriptsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r update scripts too many requests response has a 5xx status code
func (o *RTRUpdateScriptsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r update scripts too many requests response a status code equal to that given
func (o *RTRUpdateScriptsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the r t r update scripts too many requests response
func (o *RTRUpdateScriptsTooManyRequests) Code() int {
	return 429
}

func (o *RTRUpdateScriptsTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRUpdateScriptsTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /real-time-response/entities/scripts/v1][%d] rTRUpdateScriptsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRUpdateScriptsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRUpdateScriptsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
