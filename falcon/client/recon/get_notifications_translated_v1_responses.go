// Code generated by go-swagger; DO NOT EDIT.

package recon

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

// GetNotificationsTranslatedV1Reader is a Reader for the GetNotificationsTranslatedV1 structure.
type GetNotificationsTranslatedV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetNotificationsTranslatedV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetNotificationsTranslatedV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetNotificationsTranslatedV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetNotificationsTranslatedV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetNotificationsTranslatedV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetNotificationsTranslatedV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetNotificationsTranslatedV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /recon/entities/notifications-translated/v1] GetNotificationsTranslatedV1", response, response.Code())
	}
}

// NewGetNotificationsTranslatedV1OK creates a GetNotificationsTranslatedV1OK with default headers values
func NewGetNotificationsTranslatedV1OK() *GetNotificationsTranslatedV1OK {
	return &GetNotificationsTranslatedV1OK{}
}

/*
GetNotificationsTranslatedV1OK describes a response with status code 200, with default header values.

OK
*/
type GetNotificationsTranslatedV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainNotificationEntitiesResponseV1
}

// IsSuccess returns true when this get notifications translated v1 o k response has a 2xx status code
func (o *GetNotificationsTranslatedV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get notifications translated v1 o k response has a 3xx status code
func (o *GetNotificationsTranslatedV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get notifications translated v1 o k response has a 4xx status code
func (o *GetNotificationsTranslatedV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get notifications translated v1 o k response has a 5xx status code
func (o *GetNotificationsTranslatedV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get notifications translated v1 o k response a status code equal to that given
func (o *GetNotificationsTranslatedV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get notifications translated v1 o k response
func (o *GetNotificationsTranslatedV1OK) Code() int {
	return 200
}

func (o *GetNotificationsTranslatedV1OK) Error() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1OK  %+v", 200, o.Payload)
}

func (o *GetNotificationsTranslatedV1OK) String() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1OK  %+v", 200, o.Payload)
}

func (o *GetNotificationsTranslatedV1OK) GetPayload() *models.DomainNotificationEntitiesResponseV1 {
	return o.Payload
}

func (o *GetNotificationsTranslatedV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainNotificationEntitiesResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetNotificationsTranslatedV1BadRequest creates a GetNotificationsTranslatedV1BadRequest with default headers values
func NewGetNotificationsTranslatedV1BadRequest() *GetNotificationsTranslatedV1BadRequest {
	return &GetNotificationsTranslatedV1BadRequest{}
}

/*
GetNotificationsTranslatedV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetNotificationsTranslatedV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this get notifications translated v1 bad request response has a 2xx status code
func (o *GetNotificationsTranslatedV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get notifications translated v1 bad request response has a 3xx status code
func (o *GetNotificationsTranslatedV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get notifications translated v1 bad request response has a 4xx status code
func (o *GetNotificationsTranslatedV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get notifications translated v1 bad request response has a 5xx status code
func (o *GetNotificationsTranslatedV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get notifications translated v1 bad request response a status code equal to that given
func (o *GetNotificationsTranslatedV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get notifications translated v1 bad request response
func (o *GetNotificationsTranslatedV1BadRequest) Code() int {
	return 400
}

func (o *GetNotificationsTranslatedV1BadRequest) Error() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1BadRequest  %+v", 400, o.Payload)
}

func (o *GetNotificationsTranslatedV1BadRequest) String() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1BadRequest  %+v", 400, o.Payload)
}

func (o *GetNotificationsTranslatedV1BadRequest) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *GetNotificationsTranslatedV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetNotificationsTranslatedV1Unauthorized creates a GetNotificationsTranslatedV1Unauthorized with default headers values
func NewGetNotificationsTranslatedV1Unauthorized() *GetNotificationsTranslatedV1Unauthorized {
	return &GetNotificationsTranslatedV1Unauthorized{}
}

/*
GetNotificationsTranslatedV1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetNotificationsTranslatedV1Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this get notifications translated v1 unauthorized response has a 2xx status code
func (o *GetNotificationsTranslatedV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get notifications translated v1 unauthorized response has a 3xx status code
func (o *GetNotificationsTranslatedV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get notifications translated v1 unauthorized response has a 4xx status code
func (o *GetNotificationsTranslatedV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get notifications translated v1 unauthorized response has a 5xx status code
func (o *GetNotificationsTranslatedV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get notifications translated v1 unauthorized response a status code equal to that given
func (o *GetNotificationsTranslatedV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get notifications translated v1 unauthorized response
func (o *GetNotificationsTranslatedV1Unauthorized) Code() int {
	return 401
}

func (o *GetNotificationsTranslatedV1Unauthorized) Error() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1Unauthorized  %+v", 401, o.Payload)
}

func (o *GetNotificationsTranslatedV1Unauthorized) String() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1Unauthorized  %+v", 401, o.Payload)
}

func (o *GetNotificationsTranslatedV1Unauthorized) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *GetNotificationsTranslatedV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetNotificationsTranslatedV1Forbidden creates a GetNotificationsTranslatedV1Forbidden with default headers values
func NewGetNotificationsTranslatedV1Forbidden() *GetNotificationsTranslatedV1Forbidden {
	return &GetNotificationsTranslatedV1Forbidden{}
}

/*
GetNotificationsTranslatedV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetNotificationsTranslatedV1Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this get notifications translated v1 forbidden response has a 2xx status code
func (o *GetNotificationsTranslatedV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get notifications translated v1 forbidden response has a 3xx status code
func (o *GetNotificationsTranslatedV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get notifications translated v1 forbidden response has a 4xx status code
func (o *GetNotificationsTranslatedV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get notifications translated v1 forbidden response has a 5xx status code
func (o *GetNotificationsTranslatedV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get notifications translated v1 forbidden response a status code equal to that given
func (o *GetNotificationsTranslatedV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get notifications translated v1 forbidden response
func (o *GetNotificationsTranslatedV1Forbidden) Code() int {
	return 403
}

func (o *GetNotificationsTranslatedV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1Forbidden  %+v", 403, o.Payload)
}

func (o *GetNotificationsTranslatedV1Forbidden) String() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1Forbidden  %+v", 403, o.Payload)
}

func (o *GetNotificationsTranslatedV1Forbidden) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *GetNotificationsTranslatedV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetNotificationsTranslatedV1TooManyRequests creates a GetNotificationsTranslatedV1TooManyRequests with default headers values
func NewGetNotificationsTranslatedV1TooManyRequests() *GetNotificationsTranslatedV1TooManyRequests {
	return &GetNotificationsTranslatedV1TooManyRequests{}
}

/*
GetNotificationsTranslatedV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetNotificationsTranslatedV1TooManyRequests struct {

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

// IsSuccess returns true when this get notifications translated v1 too many requests response has a 2xx status code
func (o *GetNotificationsTranslatedV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get notifications translated v1 too many requests response has a 3xx status code
func (o *GetNotificationsTranslatedV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get notifications translated v1 too many requests response has a 4xx status code
func (o *GetNotificationsTranslatedV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get notifications translated v1 too many requests response has a 5xx status code
func (o *GetNotificationsTranslatedV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get notifications translated v1 too many requests response a status code equal to that given
func (o *GetNotificationsTranslatedV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get notifications translated v1 too many requests response
func (o *GetNotificationsTranslatedV1TooManyRequests) Code() int {
	return 429
}

func (o *GetNotificationsTranslatedV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetNotificationsTranslatedV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetNotificationsTranslatedV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetNotificationsTranslatedV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetNotificationsTranslatedV1InternalServerError creates a GetNotificationsTranslatedV1InternalServerError with default headers values
func NewGetNotificationsTranslatedV1InternalServerError() *GetNotificationsTranslatedV1InternalServerError {
	return &GetNotificationsTranslatedV1InternalServerError{}
}

/*
GetNotificationsTranslatedV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetNotificationsTranslatedV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this get notifications translated v1 internal server error response has a 2xx status code
func (o *GetNotificationsTranslatedV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get notifications translated v1 internal server error response has a 3xx status code
func (o *GetNotificationsTranslatedV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get notifications translated v1 internal server error response has a 4xx status code
func (o *GetNotificationsTranslatedV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get notifications translated v1 internal server error response has a 5xx status code
func (o *GetNotificationsTranslatedV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get notifications translated v1 internal server error response a status code equal to that given
func (o *GetNotificationsTranslatedV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get notifications translated v1 internal server error response
func (o *GetNotificationsTranslatedV1InternalServerError) Code() int {
	return 500
}

func (o *GetNotificationsTranslatedV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1InternalServerError  %+v", 500, o.Payload)
}

func (o *GetNotificationsTranslatedV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /recon/entities/notifications-translated/v1][%d] getNotificationsTranslatedV1InternalServerError  %+v", 500, o.Payload)
}

func (o *GetNotificationsTranslatedV1InternalServerError) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *GetNotificationsTranslatedV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
