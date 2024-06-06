// Code generated by go-swagger; DO NOT EDIT.

package user_management

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

// UpdateUserV1Reader is a Reader for the UpdateUserV1 structure.
type UpdateUserV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateUserV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateUserV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateUserV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateUserV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateUserV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdateUserV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /user-management/entities/users/v1] updateUserV1", response, response.Code())
	}
}

// NewUpdateUserV1OK creates a UpdateUserV1OK with default headers values
func NewUpdateUserV1OK() *UpdateUserV1OK {
	return &UpdateUserV1OK{}
}

/*
UpdateUserV1OK describes a response with status code 200, with default header values.

OK
*/
type UpdateUserV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FlightcontrolapiUserResponse
}

// IsSuccess returns true when this update user v1 o k response has a 2xx status code
func (o *UpdateUserV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update user v1 o k response has a 3xx status code
func (o *UpdateUserV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user v1 o k response has a 4xx status code
func (o *UpdateUserV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update user v1 o k response has a 5xx status code
func (o *UpdateUserV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this update user v1 o k response a status code equal to that given
func (o *UpdateUserV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update user v1 o k response
func (o *UpdateUserV1OK) Code() int {
	return 200
}

func (o *UpdateUserV1OK) Error() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1OK  %+v", 200, o.Payload)
}

func (o *UpdateUserV1OK) String() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1OK  %+v", 200, o.Payload)
}

func (o *UpdateUserV1OK) GetPayload() *models.FlightcontrolapiUserResponse {
	return o.Payload
}

func (o *UpdateUserV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FlightcontrolapiUserResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserV1BadRequest creates a UpdateUserV1BadRequest with default headers values
func NewUpdateUserV1BadRequest() *UpdateUserV1BadRequest {
	return &UpdateUserV1BadRequest{}
}

/*
UpdateUserV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdateUserV1BadRequest struct {

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

// IsSuccess returns true when this update user v1 bad request response has a 2xx status code
func (o *UpdateUserV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user v1 bad request response has a 3xx status code
func (o *UpdateUserV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user v1 bad request response has a 4xx status code
func (o *UpdateUserV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user v1 bad request response has a 5xx status code
func (o *UpdateUserV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update user v1 bad request response a status code equal to that given
func (o *UpdateUserV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update user v1 bad request response
func (o *UpdateUserV1BadRequest) Code() int {
	return 400
}

func (o *UpdateUserV1BadRequest) Error() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1BadRequest  %+v", 400, o.Payload)
}

func (o *UpdateUserV1BadRequest) String() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1BadRequest  %+v", 400, o.Payload)
}

func (o *UpdateUserV1BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdateUserV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateUserV1Forbidden creates a UpdateUserV1Forbidden with default headers values
func NewUpdateUserV1Forbidden() *UpdateUserV1Forbidden {
	return &UpdateUserV1Forbidden{}
}

/*
UpdateUserV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateUserV1Forbidden struct {

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

// IsSuccess returns true when this update user v1 forbidden response has a 2xx status code
func (o *UpdateUserV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user v1 forbidden response has a 3xx status code
func (o *UpdateUserV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user v1 forbidden response has a 4xx status code
func (o *UpdateUserV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user v1 forbidden response has a 5xx status code
func (o *UpdateUserV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update user v1 forbidden response a status code equal to that given
func (o *UpdateUserV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update user v1 forbidden response
func (o *UpdateUserV1Forbidden) Code() int {
	return 403
}

func (o *UpdateUserV1Forbidden) Error() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1Forbidden  %+v", 403, o.Payload)
}

func (o *UpdateUserV1Forbidden) String() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1Forbidden  %+v", 403, o.Payload)
}

func (o *UpdateUserV1Forbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdateUserV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateUserV1TooManyRequests creates a UpdateUserV1TooManyRequests with default headers values
func NewUpdateUserV1TooManyRequests() *UpdateUserV1TooManyRequests {
	return &UpdateUserV1TooManyRequests{}
}

/*
UpdateUserV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdateUserV1TooManyRequests struct {

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

// IsSuccess returns true when this update user v1 too many requests response has a 2xx status code
func (o *UpdateUserV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user v1 too many requests response has a 3xx status code
func (o *UpdateUserV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user v1 too many requests response has a 4xx status code
func (o *UpdateUserV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user v1 too many requests response has a 5xx status code
func (o *UpdateUserV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update user v1 too many requests response a status code equal to that given
func (o *UpdateUserV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update user v1 too many requests response
func (o *UpdateUserV1TooManyRequests) Code() int {
	return 429
}

func (o *UpdateUserV1TooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateUserV1TooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateUserV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateUserV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateUserV1InternalServerError creates a UpdateUserV1InternalServerError with default headers values
func NewUpdateUserV1InternalServerError() *UpdateUserV1InternalServerError {
	return &UpdateUserV1InternalServerError{}
}

/*
UpdateUserV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdateUserV1InternalServerError struct {

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

// IsSuccess returns true when this update user v1 internal server error response has a 2xx status code
func (o *UpdateUserV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user v1 internal server error response has a 3xx status code
func (o *UpdateUserV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user v1 internal server error response has a 4xx status code
func (o *UpdateUserV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update user v1 internal server error response has a 5xx status code
func (o *UpdateUserV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update user v1 internal server error response a status code equal to that given
func (o *UpdateUserV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update user v1 internal server error response
func (o *UpdateUserV1InternalServerError) Code() int {
	return 500
}

func (o *UpdateUserV1InternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1InternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateUserV1InternalServerError) String() string {
	return fmt.Sprintf("[PATCH /user-management/entities/users/v1][%d] updateUserV1InternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateUserV1InternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *UpdateUserV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
