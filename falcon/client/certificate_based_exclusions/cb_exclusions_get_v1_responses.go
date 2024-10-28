// Code generated by go-swagger; DO NOT EDIT.

package certificate_based_exclusions

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

// CbExclusionsGetV1Reader is a Reader for the CbExclusionsGetV1 structure.
type CbExclusionsGetV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CbExclusionsGetV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCbExclusionsGetV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCbExclusionsGetV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCbExclusionsGetV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCbExclusionsGetV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCbExclusionsGetV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCbExclusionsGetV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /exclusions/entities/cert-based-exclusions/v1] cb-exclusions.get.v1", response, response.Code())
	}
}

// NewCbExclusionsGetV1OK creates a CbExclusionsGetV1OK with default headers values
func NewCbExclusionsGetV1OK() *CbExclusionsGetV1OK {
	return &CbExclusionsGetV1OK{}
}

/*
CbExclusionsGetV1OK describes a response with status code 200, with default header values.

OK
*/
type CbExclusionsGetV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APICertBasedExclusionRespV1
}

// IsSuccess returns true when this cb exclusions get v1 o k response has a 2xx status code
func (o *CbExclusionsGetV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cb exclusions get v1 o k response has a 3xx status code
func (o *CbExclusionsGetV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cb exclusions get v1 o k response has a 4xx status code
func (o *CbExclusionsGetV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cb exclusions get v1 o k response has a 5xx status code
func (o *CbExclusionsGetV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this cb exclusions get v1 o k response a status code equal to that given
func (o *CbExclusionsGetV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cb exclusions get v1 o k response
func (o *CbExclusionsGetV1OK) Code() int {
	return 200
}

func (o *CbExclusionsGetV1OK) Error() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1OK  %+v", 200, o.Payload)
}

func (o *CbExclusionsGetV1OK) String() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1OK  %+v", 200, o.Payload)
}

func (o *CbExclusionsGetV1OK) GetPayload() *models.APICertBasedExclusionRespV1 {
	return o.Payload
}

func (o *CbExclusionsGetV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APICertBasedExclusionRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCbExclusionsGetV1BadRequest creates a CbExclusionsGetV1BadRequest with default headers values
func NewCbExclusionsGetV1BadRequest() *CbExclusionsGetV1BadRequest {
	return &CbExclusionsGetV1BadRequest{}
}

/*
CbExclusionsGetV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CbExclusionsGetV1BadRequest struct {

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

// IsSuccess returns true when this cb exclusions get v1 bad request response has a 2xx status code
func (o *CbExclusionsGetV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cb exclusions get v1 bad request response has a 3xx status code
func (o *CbExclusionsGetV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cb exclusions get v1 bad request response has a 4xx status code
func (o *CbExclusionsGetV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this cb exclusions get v1 bad request response has a 5xx status code
func (o *CbExclusionsGetV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this cb exclusions get v1 bad request response a status code equal to that given
func (o *CbExclusionsGetV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the cb exclusions get v1 bad request response
func (o *CbExclusionsGetV1BadRequest) Code() int {
	return 400
}

func (o *CbExclusionsGetV1BadRequest) Error() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1BadRequest  %+v", 400, o.Payload)
}

func (o *CbExclusionsGetV1BadRequest) String() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1BadRequest  %+v", 400, o.Payload)
}

func (o *CbExclusionsGetV1BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CbExclusionsGetV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCbExclusionsGetV1Unauthorized creates a CbExclusionsGetV1Unauthorized with default headers values
func NewCbExclusionsGetV1Unauthorized() *CbExclusionsGetV1Unauthorized {
	return &CbExclusionsGetV1Unauthorized{}
}

/*
CbExclusionsGetV1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CbExclusionsGetV1Unauthorized struct {

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

// IsSuccess returns true when this cb exclusions get v1 unauthorized response has a 2xx status code
func (o *CbExclusionsGetV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cb exclusions get v1 unauthorized response has a 3xx status code
func (o *CbExclusionsGetV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cb exclusions get v1 unauthorized response has a 4xx status code
func (o *CbExclusionsGetV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this cb exclusions get v1 unauthorized response has a 5xx status code
func (o *CbExclusionsGetV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this cb exclusions get v1 unauthorized response a status code equal to that given
func (o *CbExclusionsGetV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the cb exclusions get v1 unauthorized response
func (o *CbExclusionsGetV1Unauthorized) Code() int {
	return 401
}

func (o *CbExclusionsGetV1Unauthorized) Error() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1Unauthorized  %+v", 401, o.Payload)
}

func (o *CbExclusionsGetV1Unauthorized) String() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1Unauthorized  %+v", 401, o.Payload)
}

func (o *CbExclusionsGetV1Unauthorized) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CbExclusionsGetV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCbExclusionsGetV1Forbidden creates a CbExclusionsGetV1Forbidden with default headers values
func NewCbExclusionsGetV1Forbidden() *CbExclusionsGetV1Forbidden {
	return &CbExclusionsGetV1Forbidden{}
}

/*
CbExclusionsGetV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CbExclusionsGetV1Forbidden struct {

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

// IsSuccess returns true when this cb exclusions get v1 forbidden response has a 2xx status code
func (o *CbExclusionsGetV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cb exclusions get v1 forbidden response has a 3xx status code
func (o *CbExclusionsGetV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cb exclusions get v1 forbidden response has a 4xx status code
func (o *CbExclusionsGetV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this cb exclusions get v1 forbidden response has a 5xx status code
func (o *CbExclusionsGetV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this cb exclusions get v1 forbidden response a status code equal to that given
func (o *CbExclusionsGetV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the cb exclusions get v1 forbidden response
func (o *CbExclusionsGetV1Forbidden) Code() int {
	return 403
}

func (o *CbExclusionsGetV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1Forbidden  %+v", 403, o.Payload)
}

func (o *CbExclusionsGetV1Forbidden) String() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1Forbidden  %+v", 403, o.Payload)
}

func (o *CbExclusionsGetV1Forbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *CbExclusionsGetV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCbExclusionsGetV1TooManyRequests creates a CbExclusionsGetV1TooManyRequests with default headers values
func NewCbExclusionsGetV1TooManyRequests() *CbExclusionsGetV1TooManyRequests {
	return &CbExclusionsGetV1TooManyRequests{}
}

/*
CbExclusionsGetV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CbExclusionsGetV1TooManyRequests struct {

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

// IsSuccess returns true when this cb exclusions get v1 too many requests response has a 2xx status code
func (o *CbExclusionsGetV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cb exclusions get v1 too many requests response has a 3xx status code
func (o *CbExclusionsGetV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cb exclusions get v1 too many requests response has a 4xx status code
func (o *CbExclusionsGetV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this cb exclusions get v1 too many requests response has a 5xx status code
func (o *CbExclusionsGetV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this cb exclusions get v1 too many requests response a status code equal to that given
func (o *CbExclusionsGetV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the cb exclusions get v1 too many requests response
func (o *CbExclusionsGetV1TooManyRequests) Code() int {
	return 429
}

func (o *CbExclusionsGetV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CbExclusionsGetV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CbExclusionsGetV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CbExclusionsGetV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCbExclusionsGetV1InternalServerError creates a CbExclusionsGetV1InternalServerError with default headers values
func NewCbExclusionsGetV1InternalServerError() *CbExclusionsGetV1InternalServerError {
	return &CbExclusionsGetV1InternalServerError{}
}

/*
CbExclusionsGetV1InternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type CbExclusionsGetV1InternalServerError struct {

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

// IsSuccess returns true when this cb exclusions get v1 internal server error response has a 2xx status code
func (o *CbExclusionsGetV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cb exclusions get v1 internal server error response has a 3xx status code
func (o *CbExclusionsGetV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cb exclusions get v1 internal server error response has a 4xx status code
func (o *CbExclusionsGetV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this cb exclusions get v1 internal server error response has a 5xx status code
func (o *CbExclusionsGetV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this cb exclusions get v1 internal server error response a status code equal to that given
func (o *CbExclusionsGetV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the cb exclusions get v1 internal server error response
func (o *CbExclusionsGetV1InternalServerError) Code() int {
	return 500
}

func (o *CbExclusionsGetV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1InternalServerError  %+v", 500, o.Payload)
}

func (o *CbExclusionsGetV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /exclusions/entities/cert-based-exclusions/v1][%d] cbExclusionsGetV1InternalServerError  %+v", 500, o.Payload)
}

func (o *CbExclusionsGetV1InternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CbExclusionsGetV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
