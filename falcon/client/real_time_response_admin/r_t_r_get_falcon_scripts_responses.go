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

// RTRGetFalconScriptsReader is a Reader for the RTRGetFalconScripts structure.
type RTRGetFalconScriptsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RTRGetFalconScriptsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRTRGetFalconScriptsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRTRGetFalconScriptsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRTRGetFalconScriptsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRTRGetFalconScriptsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRTRGetFalconScriptsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewRTRGetFalconScriptsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /real-time-response/entities/falcon-scripts/v1] RTR-GetFalconScripts", response, response.Code())
	}
}

// NewRTRGetFalconScriptsOK creates a RTRGetFalconScriptsOK with default headers values
func NewRTRGetFalconScriptsOK() *RTRGetFalconScriptsOK {
	return &RTRGetFalconScriptsOK{}
}

/*
RTRGetFalconScriptsOK describes a response with status code 200, with default header values.

OK
*/
type RTRGetFalconScriptsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.EmpowerapiMsaFalconScriptResponse
}

// IsSuccess returns true when this r t r get falcon scripts o k response has a 2xx status code
func (o *RTRGetFalconScriptsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this r t r get falcon scripts o k response has a 3xx status code
func (o *RTRGetFalconScriptsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r get falcon scripts o k response has a 4xx status code
func (o *RTRGetFalconScriptsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r get falcon scripts o k response has a 5xx status code
func (o *RTRGetFalconScriptsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r get falcon scripts o k response a status code equal to that given
func (o *RTRGetFalconScriptsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the r t r get falcon scripts o k response
func (o *RTRGetFalconScriptsOK) Code() int {
	return 200
}

func (o *RTRGetFalconScriptsOK) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsOK  %+v", 200, o.Payload)
}

func (o *RTRGetFalconScriptsOK) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsOK  %+v", 200, o.Payload)
}

func (o *RTRGetFalconScriptsOK) GetPayload() *models.EmpowerapiMsaFalconScriptResponse {
	return o.Payload
}

func (o *RTRGetFalconScriptsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.EmpowerapiMsaFalconScriptResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRTRGetFalconScriptsBadRequest creates a RTRGetFalconScriptsBadRequest with default headers values
func NewRTRGetFalconScriptsBadRequest() *RTRGetFalconScriptsBadRequest {
	return &RTRGetFalconScriptsBadRequest{}
}

/*
RTRGetFalconScriptsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RTRGetFalconScriptsBadRequest struct {

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

// IsSuccess returns true when this r t r get falcon scripts bad request response has a 2xx status code
func (o *RTRGetFalconScriptsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r get falcon scripts bad request response has a 3xx status code
func (o *RTRGetFalconScriptsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r get falcon scripts bad request response has a 4xx status code
func (o *RTRGetFalconScriptsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r get falcon scripts bad request response has a 5xx status code
func (o *RTRGetFalconScriptsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r get falcon scripts bad request response a status code equal to that given
func (o *RTRGetFalconScriptsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the r t r get falcon scripts bad request response
func (o *RTRGetFalconScriptsBadRequest) Code() int {
	return 400
}

func (o *RTRGetFalconScriptsBadRequest) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRGetFalconScriptsBadRequest) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsBadRequest  %+v", 400, o.Payload)
}

func (o *RTRGetFalconScriptsBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRGetFalconScriptsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRGetFalconScriptsForbidden creates a RTRGetFalconScriptsForbidden with default headers values
func NewRTRGetFalconScriptsForbidden() *RTRGetFalconScriptsForbidden {
	return &RTRGetFalconScriptsForbidden{}
}

/*
RTRGetFalconScriptsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RTRGetFalconScriptsForbidden struct {

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

// IsSuccess returns true when this r t r get falcon scripts forbidden response has a 2xx status code
func (o *RTRGetFalconScriptsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r get falcon scripts forbidden response has a 3xx status code
func (o *RTRGetFalconScriptsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r get falcon scripts forbidden response has a 4xx status code
func (o *RTRGetFalconScriptsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r get falcon scripts forbidden response has a 5xx status code
func (o *RTRGetFalconScriptsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r get falcon scripts forbidden response a status code equal to that given
func (o *RTRGetFalconScriptsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the r t r get falcon scripts forbidden response
func (o *RTRGetFalconScriptsForbidden) Code() int {
	return 403
}

func (o *RTRGetFalconScriptsForbidden) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsForbidden  %+v", 403, o.Payload)
}

func (o *RTRGetFalconScriptsForbidden) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsForbidden  %+v", 403, o.Payload)
}

func (o *RTRGetFalconScriptsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRGetFalconScriptsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRGetFalconScriptsNotFound creates a RTRGetFalconScriptsNotFound with default headers values
func NewRTRGetFalconScriptsNotFound() *RTRGetFalconScriptsNotFound {
	return &RTRGetFalconScriptsNotFound{}
}

/*
RTRGetFalconScriptsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type RTRGetFalconScriptsNotFound struct {

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

// IsSuccess returns true when this r t r get falcon scripts not found response has a 2xx status code
func (o *RTRGetFalconScriptsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r get falcon scripts not found response has a 3xx status code
func (o *RTRGetFalconScriptsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r get falcon scripts not found response has a 4xx status code
func (o *RTRGetFalconScriptsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r get falcon scripts not found response has a 5xx status code
func (o *RTRGetFalconScriptsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r get falcon scripts not found response a status code equal to that given
func (o *RTRGetFalconScriptsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the r t r get falcon scripts not found response
func (o *RTRGetFalconScriptsNotFound) Code() int {
	return 404
}

func (o *RTRGetFalconScriptsNotFound) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsNotFound  %+v", 404, o.Payload)
}

func (o *RTRGetFalconScriptsNotFound) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsNotFound  %+v", 404, o.Payload)
}

func (o *RTRGetFalconScriptsNotFound) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRGetFalconScriptsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRGetFalconScriptsTooManyRequests creates a RTRGetFalconScriptsTooManyRequests with default headers values
func NewRTRGetFalconScriptsTooManyRequests() *RTRGetFalconScriptsTooManyRequests {
	return &RTRGetFalconScriptsTooManyRequests{}
}

/*
RTRGetFalconScriptsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RTRGetFalconScriptsTooManyRequests struct {

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

// IsSuccess returns true when this r t r get falcon scripts too many requests response has a 2xx status code
func (o *RTRGetFalconScriptsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r get falcon scripts too many requests response has a 3xx status code
func (o *RTRGetFalconScriptsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r get falcon scripts too many requests response has a 4xx status code
func (o *RTRGetFalconScriptsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r get falcon scripts too many requests response has a 5xx status code
func (o *RTRGetFalconScriptsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r get falcon scripts too many requests response a status code equal to that given
func (o *RTRGetFalconScriptsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the r t r get falcon scripts too many requests response
func (o *RTRGetFalconScriptsTooManyRequests) Code() int {
	return 429
}

func (o *RTRGetFalconScriptsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRGetFalconScriptsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRGetFalconScriptsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRGetFalconScriptsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRGetFalconScriptsInternalServerError creates a RTRGetFalconScriptsInternalServerError with default headers values
func NewRTRGetFalconScriptsInternalServerError() *RTRGetFalconScriptsInternalServerError {
	return &RTRGetFalconScriptsInternalServerError{}
}

/*
RTRGetFalconScriptsInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type RTRGetFalconScriptsInternalServerError struct {

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

// IsSuccess returns true when this r t r get falcon scripts internal server error response has a 2xx status code
func (o *RTRGetFalconScriptsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r get falcon scripts internal server error response has a 3xx status code
func (o *RTRGetFalconScriptsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r get falcon scripts internal server error response has a 4xx status code
func (o *RTRGetFalconScriptsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r get falcon scripts internal server error response has a 5xx status code
func (o *RTRGetFalconScriptsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this r t r get falcon scripts internal server error response a status code equal to that given
func (o *RTRGetFalconScriptsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the r t r get falcon scripts internal server error response
func (o *RTRGetFalconScriptsInternalServerError) Code() int {
	return 500
}

func (o *RTRGetFalconScriptsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsInternalServerError  %+v", 500, o.Payload)
}

func (o *RTRGetFalconScriptsInternalServerError) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/falcon-scripts/v1][%d] rTRGetFalconScriptsInternalServerError  %+v", 500, o.Payload)
}

func (o *RTRGetFalconScriptsInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRGetFalconScriptsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
