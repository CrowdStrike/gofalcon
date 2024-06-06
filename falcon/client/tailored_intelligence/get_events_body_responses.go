// Code generated by go-swagger; DO NOT EDIT.

package tailored_intelligence

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

// GetEventsBodyReader is a Reader for the GetEventsBody structure.
type GetEventsBodyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetEventsBodyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetEventsBodyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetEventsBodyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetEventsBodyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetEventsBodyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetEventsBodyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /ti/events/entities/events-full-body/v2] GetEventsBody", response, response.Code())
	}
}

// NewGetEventsBodyOK creates a GetEventsBodyOK with default headers values
func NewGetEventsBodyOK() *GetEventsBodyOK {
	return &GetEventsBodyOK{}
}

/*
GetEventsBodyOK describes a response with status code 200, with default header values.

OK
*/
type GetEventsBodyOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload []int64
}

// IsSuccess returns true when this get events body o k response has a 2xx status code
func (o *GetEventsBodyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get events body o k response has a 3xx status code
func (o *GetEventsBodyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get events body o k response has a 4xx status code
func (o *GetEventsBodyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get events body o k response has a 5xx status code
func (o *GetEventsBodyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get events body o k response a status code equal to that given
func (o *GetEventsBodyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get events body o k response
func (o *GetEventsBodyOK) Code() int {
	return 200
}

func (o *GetEventsBodyOK) Error() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyOK  %+v", 200, o.Payload)
}

func (o *GetEventsBodyOK) String() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyOK  %+v", 200, o.Payload)
}

func (o *GetEventsBodyOK) GetPayload() []int64 {
	return o.Payload
}

func (o *GetEventsBodyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventsBodyBadRequest creates a GetEventsBodyBadRequest with default headers values
func NewGetEventsBodyBadRequest() *GetEventsBodyBadRequest {
	return &GetEventsBodyBadRequest{}
}

/*
GetEventsBodyBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetEventsBodyBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload string
}

// IsSuccess returns true when this get events body bad request response has a 2xx status code
func (o *GetEventsBodyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get events body bad request response has a 3xx status code
func (o *GetEventsBodyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get events body bad request response has a 4xx status code
func (o *GetEventsBodyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get events body bad request response has a 5xx status code
func (o *GetEventsBodyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get events body bad request response a status code equal to that given
func (o *GetEventsBodyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get events body bad request response
func (o *GetEventsBodyBadRequest) Code() int {
	return 400
}

func (o *GetEventsBodyBadRequest) Error() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyBadRequest  %+v", 400, o.Payload)
}

func (o *GetEventsBodyBadRequest) String() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyBadRequest  %+v", 400, o.Payload)
}

func (o *GetEventsBodyBadRequest) GetPayload() string {
	return o.Payload
}

func (o *GetEventsBodyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetEventsBodyForbidden creates a GetEventsBodyForbidden with default headers values
func NewGetEventsBodyForbidden() *GetEventsBodyForbidden {
	return &GetEventsBodyForbidden{}
}

/*
GetEventsBodyForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetEventsBodyForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64
}

// IsSuccess returns true when this get events body forbidden response has a 2xx status code
func (o *GetEventsBodyForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get events body forbidden response has a 3xx status code
func (o *GetEventsBodyForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get events body forbidden response has a 4xx status code
func (o *GetEventsBodyForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get events body forbidden response has a 5xx status code
func (o *GetEventsBodyForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get events body forbidden response a status code equal to that given
func (o *GetEventsBodyForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get events body forbidden response
func (o *GetEventsBodyForbidden) Code() int {
	return 403
}

func (o *GetEventsBodyForbidden) Error() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyForbidden ", 403)
}

func (o *GetEventsBodyForbidden) String() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyForbidden ", 403)
}

func (o *GetEventsBodyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	return nil
}

// NewGetEventsBodyTooManyRequests creates a GetEventsBodyTooManyRequests with default headers values
func NewGetEventsBodyTooManyRequests() *GetEventsBodyTooManyRequests {
	return &GetEventsBodyTooManyRequests{}
}

/*
GetEventsBodyTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetEventsBodyTooManyRequests struct {

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

// IsSuccess returns true when this get events body too many requests response has a 2xx status code
func (o *GetEventsBodyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get events body too many requests response has a 3xx status code
func (o *GetEventsBodyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get events body too many requests response has a 4xx status code
func (o *GetEventsBodyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get events body too many requests response has a 5xx status code
func (o *GetEventsBodyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get events body too many requests response a status code equal to that given
func (o *GetEventsBodyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get events body too many requests response
func (o *GetEventsBodyTooManyRequests) Code() int {
	return 429
}

func (o *GetEventsBodyTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetEventsBodyTooManyRequests) String() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetEventsBodyTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetEventsBodyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetEventsBodyInternalServerError creates a GetEventsBodyInternalServerError with default headers values
func NewGetEventsBodyInternalServerError() *GetEventsBodyInternalServerError {
	return &GetEventsBodyInternalServerError{}
}

/*
GetEventsBodyInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetEventsBodyInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload []int64
}

// IsSuccess returns true when this get events body internal server error response has a 2xx status code
func (o *GetEventsBodyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get events body internal server error response has a 3xx status code
func (o *GetEventsBodyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get events body internal server error response has a 4xx status code
func (o *GetEventsBodyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get events body internal server error response has a 5xx status code
func (o *GetEventsBodyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get events body internal server error response a status code equal to that given
func (o *GetEventsBodyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get events body internal server error response
func (o *GetEventsBodyInternalServerError) Code() int {
	return 500
}

func (o *GetEventsBodyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyInternalServerError  %+v", 500, o.Payload)
}

func (o *GetEventsBodyInternalServerError) String() string {
	return fmt.Sprintf("[GET /ti/events/entities/events-full-body/v2][%d] getEventsBodyInternalServerError  %+v", 500, o.Payload)
}

func (o *GetEventsBodyInternalServerError) GetPayload() []int64 {
	return o.Payload
}

func (o *GetEventsBodyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
