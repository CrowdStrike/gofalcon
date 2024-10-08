// Code generated by go-swagger; DO NOT EDIT.

package filevantage

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

// GetActionsMixin0Reader is a Reader for the GetActionsMixin0 structure.
type GetActionsMixin0Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetActionsMixin0Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetActionsMixin0OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetActionsMixin0BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetActionsMixin0Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetActionsMixin0TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetActionsMixin0InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /filevantage/entities/actions/v1] getActionsMixin0", response, response.Code())
	}
}

// NewGetActionsMixin0OK creates a GetActionsMixin0OK with default headers values
func NewGetActionsMixin0OK() *GetActionsMixin0OK {
	return &GetActionsMixin0OK{}
}

/*
GetActionsMixin0OK describes a response with status code 200, with default header values.

OK
*/
type GetActionsMixin0OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ActionsGetActionResponse
}

// IsSuccess returns true when this get actions mixin0 o k response has a 2xx status code
func (o *GetActionsMixin0OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get actions mixin0 o k response has a 3xx status code
func (o *GetActionsMixin0OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get actions mixin0 o k response has a 4xx status code
func (o *GetActionsMixin0OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get actions mixin0 o k response has a 5xx status code
func (o *GetActionsMixin0OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get actions mixin0 o k response a status code equal to that given
func (o *GetActionsMixin0OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get actions mixin0 o k response
func (o *GetActionsMixin0OK) Code() int {
	return 200
}

func (o *GetActionsMixin0OK) Error() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0OK  %+v", 200, o.Payload)
}

func (o *GetActionsMixin0OK) String() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0OK  %+v", 200, o.Payload)
}

func (o *GetActionsMixin0OK) GetPayload() *models.ActionsGetActionResponse {
	return o.Payload
}

func (o *GetActionsMixin0OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ActionsGetActionResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetActionsMixin0BadRequest creates a GetActionsMixin0BadRequest with default headers values
func NewGetActionsMixin0BadRequest() *GetActionsMixin0BadRequest {
	return &GetActionsMixin0BadRequest{}
}

/*
GetActionsMixin0BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetActionsMixin0BadRequest struct {

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

// IsSuccess returns true when this get actions mixin0 bad request response has a 2xx status code
func (o *GetActionsMixin0BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get actions mixin0 bad request response has a 3xx status code
func (o *GetActionsMixin0BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get actions mixin0 bad request response has a 4xx status code
func (o *GetActionsMixin0BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get actions mixin0 bad request response has a 5xx status code
func (o *GetActionsMixin0BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get actions mixin0 bad request response a status code equal to that given
func (o *GetActionsMixin0BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get actions mixin0 bad request response
func (o *GetActionsMixin0BadRequest) Code() int {
	return 400
}

func (o *GetActionsMixin0BadRequest) Error() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0BadRequest  %+v", 400, o.Payload)
}

func (o *GetActionsMixin0BadRequest) String() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0BadRequest  %+v", 400, o.Payload)
}

func (o *GetActionsMixin0BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetActionsMixin0BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetActionsMixin0Forbidden creates a GetActionsMixin0Forbidden with default headers values
func NewGetActionsMixin0Forbidden() *GetActionsMixin0Forbidden {
	return &GetActionsMixin0Forbidden{}
}

/*
GetActionsMixin0Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetActionsMixin0Forbidden struct {

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

// IsSuccess returns true when this get actions mixin0 forbidden response has a 2xx status code
func (o *GetActionsMixin0Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get actions mixin0 forbidden response has a 3xx status code
func (o *GetActionsMixin0Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get actions mixin0 forbidden response has a 4xx status code
func (o *GetActionsMixin0Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get actions mixin0 forbidden response has a 5xx status code
func (o *GetActionsMixin0Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get actions mixin0 forbidden response a status code equal to that given
func (o *GetActionsMixin0Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get actions mixin0 forbidden response
func (o *GetActionsMixin0Forbidden) Code() int {
	return 403
}

func (o *GetActionsMixin0Forbidden) Error() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0Forbidden  %+v", 403, o.Payload)
}

func (o *GetActionsMixin0Forbidden) String() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0Forbidden  %+v", 403, o.Payload)
}

func (o *GetActionsMixin0Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetActionsMixin0Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetActionsMixin0TooManyRequests creates a GetActionsMixin0TooManyRequests with default headers values
func NewGetActionsMixin0TooManyRequests() *GetActionsMixin0TooManyRequests {
	return &GetActionsMixin0TooManyRequests{}
}

/*
GetActionsMixin0TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetActionsMixin0TooManyRequests struct {

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

// IsSuccess returns true when this get actions mixin0 too many requests response has a 2xx status code
func (o *GetActionsMixin0TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get actions mixin0 too many requests response has a 3xx status code
func (o *GetActionsMixin0TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get actions mixin0 too many requests response has a 4xx status code
func (o *GetActionsMixin0TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get actions mixin0 too many requests response has a 5xx status code
func (o *GetActionsMixin0TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get actions mixin0 too many requests response a status code equal to that given
func (o *GetActionsMixin0TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get actions mixin0 too many requests response
func (o *GetActionsMixin0TooManyRequests) Code() int {
	return 429
}

func (o *GetActionsMixin0TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetActionsMixin0TooManyRequests) String() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetActionsMixin0TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetActionsMixin0TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetActionsMixin0InternalServerError creates a GetActionsMixin0InternalServerError with default headers values
func NewGetActionsMixin0InternalServerError() *GetActionsMixin0InternalServerError {
	return &GetActionsMixin0InternalServerError{}
}

/*
GetActionsMixin0InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetActionsMixin0InternalServerError struct {

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

// IsSuccess returns true when this get actions mixin0 internal server error response has a 2xx status code
func (o *GetActionsMixin0InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get actions mixin0 internal server error response has a 3xx status code
func (o *GetActionsMixin0InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get actions mixin0 internal server error response has a 4xx status code
func (o *GetActionsMixin0InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get actions mixin0 internal server error response has a 5xx status code
func (o *GetActionsMixin0InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get actions mixin0 internal server error response a status code equal to that given
func (o *GetActionsMixin0InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get actions mixin0 internal server error response
func (o *GetActionsMixin0InternalServerError) Code() int {
	return 500
}

func (o *GetActionsMixin0InternalServerError) Error() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0InternalServerError  %+v", 500, o.Payload)
}

func (o *GetActionsMixin0InternalServerError) String() string {
	return fmt.Sprintf("[GET /filevantage/entities/actions/v1][%d] getActionsMixin0InternalServerError  %+v", 500, o.Payload)
}

func (o *GetActionsMixin0InternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetActionsMixin0InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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