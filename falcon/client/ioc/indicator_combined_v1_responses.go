// Code generated by go-swagger; DO NOT EDIT.

package ioc

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

// IndicatorCombinedV1Reader is a Reader for the IndicatorCombinedV1 structure.
type IndicatorCombinedV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndicatorCombinedV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIndicatorCombinedV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewIndicatorCombinedV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewIndicatorCombinedV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewIndicatorCombinedV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewIndicatorCombinedV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /iocs/combined/indicator/v1] indicator.combined.v1", response, response.Code())
	}
}

// NewIndicatorCombinedV1OK creates a IndicatorCombinedV1OK with default headers values
func NewIndicatorCombinedV1OK() *IndicatorCombinedV1OK {
	return &IndicatorCombinedV1OK{}
}

/*
IndicatorCombinedV1OK describes a response with status code 200, with default header values.

OK
*/
type IndicatorCombinedV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIIndicatorRespV1
}

// IsSuccess returns true when this indicator combined v1 o k response has a 2xx status code
func (o *IndicatorCombinedV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indicator combined v1 o k response has a 3xx status code
func (o *IndicatorCombinedV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator combined v1 o k response has a 4xx status code
func (o *IndicatorCombinedV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this indicator combined v1 o k response has a 5xx status code
func (o *IndicatorCombinedV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator combined v1 o k response a status code equal to that given
func (o *IndicatorCombinedV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the indicator combined v1 o k response
func (o *IndicatorCombinedV1OK) Code() int {
	return 200
}

func (o *IndicatorCombinedV1OK) Error() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1OK  %+v", 200, o.Payload)
}

func (o *IndicatorCombinedV1OK) String() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1OK  %+v", 200, o.Payload)
}

func (o *IndicatorCombinedV1OK) GetPayload() *models.APIIndicatorRespV1 {
	return o.Payload
}

func (o *IndicatorCombinedV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIIndicatorRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndicatorCombinedV1BadRequest creates a IndicatorCombinedV1BadRequest with default headers values
func NewIndicatorCombinedV1BadRequest() *IndicatorCombinedV1BadRequest {
	return &IndicatorCombinedV1BadRequest{}
}

/*
IndicatorCombinedV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type IndicatorCombinedV1BadRequest struct {

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

// IsSuccess returns true when this indicator combined v1 bad request response has a 2xx status code
func (o *IndicatorCombinedV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator combined v1 bad request response has a 3xx status code
func (o *IndicatorCombinedV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator combined v1 bad request response has a 4xx status code
func (o *IndicatorCombinedV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator combined v1 bad request response has a 5xx status code
func (o *IndicatorCombinedV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator combined v1 bad request response a status code equal to that given
func (o *IndicatorCombinedV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the indicator combined v1 bad request response
func (o *IndicatorCombinedV1BadRequest) Code() int {
	return 400
}

func (o *IndicatorCombinedV1BadRequest) Error() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1BadRequest  %+v", 400, o.Payload)
}

func (o *IndicatorCombinedV1BadRequest) String() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1BadRequest  %+v", 400, o.Payload)
}

func (o *IndicatorCombinedV1BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IndicatorCombinedV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorCombinedV1Forbidden creates a IndicatorCombinedV1Forbidden with default headers values
func NewIndicatorCombinedV1Forbidden() *IndicatorCombinedV1Forbidden {
	return &IndicatorCombinedV1Forbidden{}
}

/*
IndicatorCombinedV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type IndicatorCombinedV1Forbidden struct {

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

// IsSuccess returns true when this indicator combined v1 forbidden response has a 2xx status code
func (o *IndicatorCombinedV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator combined v1 forbidden response has a 3xx status code
func (o *IndicatorCombinedV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator combined v1 forbidden response has a 4xx status code
func (o *IndicatorCombinedV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator combined v1 forbidden response has a 5xx status code
func (o *IndicatorCombinedV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator combined v1 forbidden response a status code equal to that given
func (o *IndicatorCombinedV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the indicator combined v1 forbidden response
func (o *IndicatorCombinedV1Forbidden) Code() int {
	return 403
}

func (o *IndicatorCombinedV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1Forbidden  %+v", 403, o.Payload)
}

func (o *IndicatorCombinedV1Forbidden) String() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1Forbidden  %+v", 403, o.Payload)
}

func (o *IndicatorCombinedV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorCombinedV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorCombinedV1TooManyRequests creates a IndicatorCombinedV1TooManyRequests with default headers values
func NewIndicatorCombinedV1TooManyRequests() *IndicatorCombinedV1TooManyRequests {
	return &IndicatorCombinedV1TooManyRequests{}
}

/*
IndicatorCombinedV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type IndicatorCombinedV1TooManyRequests struct {

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

// IsSuccess returns true when this indicator combined v1 too many requests response has a 2xx status code
func (o *IndicatorCombinedV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator combined v1 too many requests response has a 3xx status code
func (o *IndicatorCombinedV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator combined v1 too many requests response has a 4xx status code
func (o *IndicatorCombinedV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator combined v1 too many requests response has a 5xx status code
func (o *IndicatorCombinedV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator combined v1 too many requests response a status code equal to that given
func (o *IndicatorCombinedV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the indicator combined v1 too many requests response
func (o *IndicatorCombinedV1TooManyRequests) Code() int {
	return 429
}

func (o *IndicatorCombinedV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IndicatorCombinedV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IndicatorCombinedV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorCombinedV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorCombinedV1InternalServerError creates a IndicatorCombinedV1InternalServerError with default headers values
func NewIndicatorCombinedV1InternalServerError() *IndicatorCombinedV1InternalServerError {
	return &IndicatorCombinedV1InternalServerError{}
}

/*
IndicatorCombinedV1InternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type IndicatorCombinedV1InternalServerError struct {

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

// IsSuccess returns true when this indicator combined v1 internal server error response has a 2xx status code
func (o *IndicatorCombinedV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator combined v1 internal server error response has a 3xx status code
func (o *IndicatorCombinedV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator combined v1 internal server error response has a 4xx status code
func (o *IndicatorCombinedV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this indicator combined v1 internal server error response has a 5xx status code
func (o *IndicatorCombinedV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this indicator combined v1 internal server error response a status code equal to that given
func (o *IndicatorCombinedV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the indicator combined v1 internal server error response
func (o *IndicatorCombinedV1InternalServerError) Code() int {
	return 500
}

func (o *IndicatorCombinedV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1InternalServerError  %+v", 500, o.Payload)
}

func (o *IndicatorCombinedV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /iocs/combined/indicator/v1][%d] indicatorCombinedV1InternalServerError  %+v", 500, o.Payload)
}

func (o *IndicatorCombinedV1InternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorCombinedV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
