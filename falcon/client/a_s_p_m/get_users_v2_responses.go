// Code generated by go-swagger; DO NOT EDIT.

package a_s_p_m

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

// GetUsersV2Reader is a Reader for the GetUsersV2 structure.
type GetUsersV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetUsersV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetUsersV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetUsersV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetUsersV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetUsersV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetUsersV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetUsersV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /aspm-api-gateway/api/v1/users/v2] get_/users/v2", response, response.Code())
	}
}

// NewGetUsersV2OK creates a GetUsersV2OK with default headers values
func NewGetUsersV2OK() *GetUsersV2OK {
	return &GetUsersV2OK{}
}

/*
GetUsersV2OK describes a response with status code 200, with default header values.

OK
*/
type GetUsersV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesUsersResponse
}

// IsSuccess returns true when this get users v2 o k response has a 2xx status code
func (o *GetUsersV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get users v2 o k response has a 3xx status code
func (o *GetUsersV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get users v2 o k response has a 4xx status code
func (o *GetUsersV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get users v2 o k response has a 5xx status code
func (o *GetUsersV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get users v2 o k response a status code equal to that given
func (o *GetUsersV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get users v2 o k response
func (o *GetUsersV2OK) Code() int {
	return 200
}

func (o *GetUsersV2OK) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2OK  %+v", 200, o.Payload)
}

func (o *GetUsersV2OK) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2OK  %+v", 200, o.Payload)
}

func (o *GetUsersV2OK) GetPayload() *models.TypesUsersResponse {
	return o.Payload
}

func (o *GetUsersV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesUsersResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUsersV2BadRequest creates a GetUsersV2BadRequest with default headers values
func NewGetUsersV2BadRequest() *GetUsersV2BadRequest {
	return &GetUsersV2BadRequest{}
}

/*
GetUsersV2BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetUsersV2BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get users v2 bad request response has a 2xx status code
func (o *GetUsersV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get users v2 bad request response has a 3xx status code
func (o *GetUsersV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get users v2 bad request response has a 4xx status code
func (o *GetUsersV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get users v2 bad request response has a 5xx status code
func (o *GetUsersV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get users v2 bad request response a status code equal to that given
func (o *GetUsersV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get users v2 bad request response
func (o *GetUsersV2BadRequest) Code() int {
	return 400
}

func (o *GetUsersV2BadRequest) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2BadRequest  %+v", 400, o.Payload)
}

func (o *GetUsersV2BadRequest) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2BadRequest  %+v", 400, o.Payload)
}

func (o *GetUsersV2BadRequest) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetUsersV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUsersV2Unauthorized creates a GetUsersV2Unauthorized with default headers values
func NewGetUsersV2Unauthorized() *GetUsersV2Unauthorized {
	return &GetUsersV2Unauthorized{}
}

/*
GetUsersV2Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetUsersV2Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get users v2 unauthorized response has a 2xx status code
func (o *GetUsersV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get users v2 unauthorized response has a 3xx status code
func (o *GetUsersV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get users v2 unauthorized response has a 4xx status code
func (o *GetUsersV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get users v2 unauthorized response has a 5xx status code
func (o *GetUsersV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get users v2 unauthorized response a status code equal to that given
func (o *GetUsersV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get users v2 unauthorized response
func (o *GetUsersV2Unauthorized) Code() int {
	return 401
}

func (o *GetUsersV2Unauthorized) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2Unauthorized  %+v", 401, o.Payload)
}

func (o *GetUsersV2Unauthorized) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2Unauthorized  %+v", 401, o.Payload)
}

func (o *GetUsersV2Unauthorized) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetUsersV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUsersV2Forbidden creates a GetUsersV2Forbidden with default headers values
func NewGetUsersV2Forbidden() *GetUsersV2Forbidden {
	return &GetUsersV2Forbidden{}
}

/*
GetUsersV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetUsersV2Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get users v2 forbidden response has a 2xx status code
func (o *GetUsersV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get users v2 forbidden response has a 3xx status code
func (o *GetUsersV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get users v2 forbidden response has a 4xx status code
func (o *GetUsersV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get users v2 forbidden response has a 5xx status code
func (o *GetUsersV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get users v2 forbidden response a status code equal to that given
func (o *GetUsersV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get users v2 forbidden response
func (o *GetUsersV2Forbidden) Code() int {
	return 403
}

func (o *GetUsersV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetUsersV2Forbidden) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetUsersV2Forbidden) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetUsersV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUsersV2TooManyRequests creates a GetUsersV2TooManyRequests with default headers values
func NewGetUsersV2TooManyRequests() *GetUsersV2TooManyRequests {
	return &GetUsersV2TooManyRequests{}
}

/*
GetUsersV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetUsersV2TooManyRequests struct {

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

// IsSuccess returns true when this get users v2 too many requests response has a 2xx status code
func (o *GetUsersV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get users v2 too many requests response has a 3xx status code
func (o *GetUsersV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get users v2 too many requests response has a 4xx status code
func (o *GetUsersV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get users v2 too many requests response has a 5xx status code
func (o *GetUsersV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get users v2 too many requests response a status code equal to that given
func (o *GetUsersV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get users v2 too many requests response
func (o *GetUsersV2TooManyRequests) Code() int {
	return 429
}

func (o *GetUsersV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetUsersV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetUsersV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetUsersV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetUsersV2InternalServerError creates a GetUsersV2InternalServerError with default headers values
func NewGetUsersV2InternalServerError() *GetUsersV2InternalServerError {
	return &GetUsersV2InternalServerError{}
}

/*
GetUsersV2InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetUsersV2InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get users v2 internal server error response has a 2xx status code
func (o *GetUsersV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get users v2 internal server error response has a 3xx status code
func (o *GetUsersV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get users v2 internal server error response has a 4xx status code
func (o *GetUsersV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get users v2 internal server error response has a 5xx status code
func (o *GetUsersV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get users v2 internal server error response a status code equal to that given
func (o *GetUsersV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get users v2 internal server error response
func (o *GetUsersV2InternalServerError) Code() int {
	return 500
}

func (o *GetUsersV2InternalServerError) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2InternalServerError  %+v", 500, o.Payload)
}

func (o *GetUsersV2InternalServerError) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/users/v2][%d] getUsersV2InternalServerError  %+v", 500, o.Payload)
}

func (o *GetUsersV2InternalServerError) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetUsersV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
