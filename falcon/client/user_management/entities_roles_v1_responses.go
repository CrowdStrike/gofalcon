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

// EntitiesRolesV1Reader is a Reader for the EntitiesRolesV1 structure.
type EntitiesRolesV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EntitiesRolesV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEntitiesRolesV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewEntitiesRolesV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewEntitiesRolesV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewEntitiesRolesV1NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewEntitiesRolesV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewEntitiesRolesV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /user-management/entities/roles/v1] entitiesRolesV1", response, response.Code())
	}
}

// NewEntitiesRolesV1OK creates a EntitiesRolesV1OK with default headers values
func NewEntitiesRolesV1OK() *EntitiesRolesV1OK {
	return &EntitiesRolesV1OK{}
}

/*
EntitiesRolesV1OK describes a response with status code 200, with default header values.

OK
*/
type EntitiesRolesV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FlightcontrolapiGetRolesResponse
}

// IsSuccess returns true when this entities roles v1 o k response has a 2xx status code
func (o *EntitiesRolesV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this entities roles v1 o k response has a 3xx status code
func (o *EntitiesRolesV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities roles v1 o k response has a 4xx status code
func (o *EntitiesRolesV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this entities roles v1 o k response has a 5xx status code
func (o *EntitiesRolesV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this entities roles v1 o k response a status code equal to that given
func (o *EntitiesRolesV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the entities roles v1 o k response
func (o *EntitiesRolesV1OK) Code() int {
	return 200
}

func (o *EntitiesRolesV1OK) Error() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1OK  %+v", 200, o.Payload)
}

func (o *EntitiesRolesV1OK) String() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1OK  %+v", 200, o.Payload)
}

func (o *EntitiesRolesV1OK) GetPayload() *models.FlightcontrolapiGetRolesResponse {
	return o.Payload
}

func (o *EntitiesRolesV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FlightcontrolapiGetRolesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEntitiesRolesV1BadRequest creates a EntitiesRolesV1BadRequest with default headers values
func NewEntitiesRolesV1BadRequest() *EntitiesRolesV1BadRequest {
	return &EntitiesRolesV1BadRequest{}
}

/*
EntitiesRolesV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type EntitiesRolesV1BadRequest struct {

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

// IsSuccess returns true when this entities roles v1 bad request response has a 2xx status code
func (o *EntitiesRolesV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities roles v1 bad request response has a 3xx status code
func (o *EntitiesRolesV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities roles v1 bad request response has a 4xx status code
func (o *EntitiesRolesV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities roles v1 bad request response has a 5xx status code
func (o *EntitiesRolesV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this entities roles v1 bad request response a status code equal to that given
func (o *EntitiesRolesV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the entities roles v1 bad request response
func (o *EntitiesRolesV1BadRequest) Code() int {
	return 400
}

func (o *EntitiesRolesV1BadRequest) Error() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1BadRequest  %+v", 400, o.Payload)
}

func (o *EntitiesRolesV1BadRequest) String() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1BadRequest  %+v", 400, o.Payload)
}

func (o *EntitiesRolesV1BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *EntitiesRolesV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewEntitiesRolesV1Forbidden creates a EntitiesRolesV1Forbidden with default headers values
func NewEntitiesRolesV1Forbidden() *EntitiesRolesV1Forbidden {
	return &EntitiesRolesV1Forbidden{}
}

/*
EntitiesRolesV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type EntitiesRolesV1Forbidden struct {

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

// IsSuccess returns true when this entities roles v1 forbidden response has a 2xx status code
func (o *EntitiesRolesV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities roles v1 forbidden response has a 3xx status code
func (o *EntitiesRolesV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities roles v1 forbidden response has a 4xx status code
func (o *EntitiesRolesV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities roles v1 forbidden response has a 5xx status code
func (o *EntitiesRolesV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this entities roles v1 forbidden response a status code equal to that given
func (o *EntitiesRolesV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the entities roles v1 forbidden response
func (o *EntitiesRolesV1Forbidden) Code() int {
	return 403
}

func (o *EntitiesRolesV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1Forbidden  %+v", 403, o.Payload)
}

func (o *EntitiesRolesV1Forbidden) String() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1Forbidden  %+v", 403, o.Payload)
}

func (o *EntitiesRolesV1Forbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *EntitiesRolesV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewEntitiesRolesV1NotFound creates a EntitiesRolesV1NotFound with default headers values
func NewEntitiesRolesV1NotFound() *EntitiesRolesV1NotFound {
	return &EntitiesRolesV1NotFound{}
}

/*
EntitiesRolesV1NotFound describes a response with status code 404, with default header values.

Not Found
*/
type EntitiesRolesV1NotFound struct {

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

// IsSuccess returns true when this entities roles v1 not found response has a 2xx status code
func (o *EntitiesRolesV1NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities roles v1 not found response has a 3xx status code
func (o *EntitiesRolesV1NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities roles v1 not found response has a 4xx status code
func (o *EntitiesRolesV1NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities roles v1 not found response has a 5xx status code
func (o *EntitiesRolesV1NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this entities roles v1 not found response a status code equal to that given
func (o *EntitiesRolesV1NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the entities roles v1 not found response
func (o *EntitiesRolesV1NotFound) Code() int {
	return 404
}

func (o *EntitiesRolesV1NotFound) Error() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1NotFound  %+v", 404, o.Payload)
}

func (o *EntitiesRolesV1NotFound) String() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1NotFound  %+v", 404, o.Payload)
}

func (o *EntitiesRolesV1NotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *EntitiesRolesV1NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewEntitiesRolesV1TooManyRequests creates a EntitiesRolesV1TooManyRequests with default headers values
func NewEntitiesRolesV1TooManyRequests() *EntitiesRolesV1TooManyRequests {
	return &EntitiesRolesV1TooManyRequests{}
}

/*
EntitiesRolesV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type EntitiesRolesV1TooManyRequests struct {

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

// IsSuccess returns true when this entities roles v1 too many requests response has a 2xx status code
func (o *EntitiesRolesV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities roles v1 too many requests response has a 3xx status code
func (o *EntitiesRolesV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities roles v1 too many requests response has a 4xx status code
func (o *EntitiesRolesV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this entities roles v1 too many requests response has a 5xx status code
func (o *EntitiesRolesV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this entities roles v1 too many requests response a status code equal to that given
func (o *EntitiesRolesV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the entities roles v1 too many requests response
func (o *EntitiesRolesV1TooManyRequests) Code() int {
	return 429
}

func (o *EntitiesRolesV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *EntitiesRolesV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *EntitiesRolesV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *EntitiesRolesV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewEntitiesRolesV1InternalServerError creates a EntitiesRolesV1InternalServerError with default headers values
func NewEntitiesRolesV1InternalServerError() *EntitiesRolesV1InternalServerError {
	return &EntitiesRolesV1InternalServerError{}
}

/*
EntitiesRolesV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type EntitiesRolesV1InternalServerError struct {

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

// IsSuccess returns true when this entities roles v1 internal server error response has a 2xx status code
func (o *EntitiesRolesV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this entities roles v1 internal server error response has a 3xx status code
func (o *EntitiesRolesV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this entities roles v1 internal server error response has a 4xx status code
func (o *EntitiesRolesV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this entities roles v1 internal server error response has a 5xx status code
func (o *EntitiesRolesV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this entities roles v1 internal server error response a status code equal to that given
func (o *EntitiesRolesV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the entities roles v1 internal server error response
func (o *EntitiesRolesV1InternalServerError) Code() int {
	return 500
}

func (o *EntitiesRolesV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1InternalServerError  %+v", 500, o.Payload)
}

func (o *EntitiesRolesV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /user-management/entities/roles/v1][%d] entitiesRolesV1InternalServerError  %+v", 500, o.Payload)
}

func (o *EntitiesRolesV1InternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *EntitiesRolesV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
