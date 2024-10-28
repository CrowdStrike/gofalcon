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

// IndicatorGetProcessesRanOnV1Reader is a Reader for the IndicatorGetProcessesRanOnV1 structure.
type IndicatorGetProcessesRanOnV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndicatorGetProcessesRanOnV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIndicatorGetProcessesRanOnV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewIndicatorGetProcessesRanOnV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewIndicatorGetProcessesRanOnV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewIndicatorGetProcessesRanOnV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /iocs/queries/indicators/processes/v1] indicator.get.processes_ran_on.v1", response, response.Code())
	}
}

// NewIndicatorGetProcessesRanOnV1OK creates a IndicatorGetProcessesRanOnV1OK with default headers values
func NewIndicatorGetProcessesRanOnV1OK() *IndicatorGetProcessesRanOnV1OK {
	return &IndicatorGetProcessesRanOnV1OK{}
}

/*
IndicatorGetProcessesRanOnV1OK describes a response with status code 200, with default header values.

OK
*/
type IndicatorGetProcessesRanOnV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIProcessesRanOnRespV1
}

// IsSuccess returns true when this indicator get processes ran on v1 o k response has a 2xx status code
func (o *IndicatorGetProcessesRanOnV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indicator get processes ran on v1 o k response has a 3xx status code
func (o *IndicatorGetProcessesRanOnV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator get processes ran on v1 o k response has a 4xx status code
func (o *IndicatorGetProcessesRanOnV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this indicator get processes ran on v1 o k response has a 5xx status code
func (o *IndicatorGetProcessesRanOnV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator get processes ran on v1 o k response a status code equal to that given
func (o *IndicatorGetProcessesRanOnV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the indicator get processes ran on v1 o k response
func (o *IndicatorGetProcessesRanOnV1OK) Code() int {
	return 200
}

func (o *IndicatorGetProcessesRanOnV1OK) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1OK  %+v", 200, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1OK) String() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1OK  %+v", 200, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1OK) GetPayload() *models.APIProcessesRanOnRespV1 {
	return o.Payload
}

func (o *IndicatorGetProcessesRanOnV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIProcessesRanOnRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndicatorGetProcessesRanOnV1Forbidden creates a IndicatorGetProcessesRanOnV1Forbidden with default headers values
func NewIndicatorGetProcessesRanOnV1Forbidden() *IndicatorGetProcessesRanOnV1Forbidden {
	return &IndicatorGetProcessesRanOnV1Forbidden{}
}

/*
IndicatorGetProcessesRanOnV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type IndicatorGetProcessesRanOnV1Forbidden struct {

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

// IsSuccess returns true when this indicator get processes ran on v1 forbidden response has a 2xx status code
func (o *IndicatorGetProcessesRanOnV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator get processes ran on v1 forbidden response has a 3xx status code
func (o *IndicatorGetProcessesRanOnV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator get processes ran on v1 forbidden response has a 4xx status code
func (o *IndicatorGetProcessesRanOnV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator get processes ran on v1 forbidden response has a 5xx status code
func (o *IndicatorGetProcessesRanOnV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator get processes ran on v1 forbidden response a status code equal to that given
func (o *IndicatorGetProcessesRanOnV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the indicator get processes ran on v1 forbidden response
func (o *IndicatorGetProcessesRanOnV1Forbidden) Code() int {
	return 403
}

func (o *IndicatorGetProcessesRanOnV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1Forbidden  %+v", 403, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1Forbidden) String() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1Forbidden  %+v", 403, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorGetProcessesRanOnV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorGetProcessesRanOnV1TooManyRequests creates a IndicatorGetProcessesRanOnV1TooManyRequests with default headers values
func NewIndicatorGetProcessesRanOnV1TooManyRequests() *IndicatorGetProcessesRanOnV1TooManyRequests {
	return &IndicatorGetProcessesRanOnV1TooManyRequests{}
}

/*
IndicatorGetProcessesRanOnV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type IndicatorGetProcessesRanOnV1TooManyRequests struct {

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

// IsSuccess returns true when this indicator get processes ran on v1 too many requests response has a 2xx status code
func (o *IndicatorGetProcessesRanOnV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator get processes ran on v1 too many requests response has a 3xx status code
func (o *IndicatorGetProcessesRanOnV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator get processes ran on v1 too many requests response has a 4xx status code
func (o *IndicatorGetProcessesRanOnV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator get processes ran on v1 too many requests response has a 5xx status code
func (o *IndicatorGetProcessesRanOnV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator get processes ran on v1 too many requests response a status code equal to that given
func (o *IndicatorGetProcessesRanOnV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the indicator get processes ran on v1 too many requests response
func (o *IndicatorGetProcessesRanOnV1TooManyRequests) Code() int {
	return 429
}

func (o *IndicatorGetProcessesRanOnV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorGetProcessesRanOnV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorGetProcessesRanOnV1InternalServerError creates a IndicatorGetProcessesRanOnV1InternalServerError with default headers values
func NewIndicatorGetProcessesRanOnV1InternalServerError() *IndicatorGetProcessesRanOnV1InternalServerError {
	return &IndicatorGetProcessesRanOnV1InternalServerError{}
}

/*
IndicatorGetProcessesRanOnV1InternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type IndicatorGetProcessesRanOnV1InternalServerError struct {

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

// IsSuccess returns true when this indicator get processes ran on v1 internal server error response has a 2xx status code
func (o *IndicatorGetProcessesRanOnV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator get processes ran on v1 internal server error response has a 3xx status code
func (o *IndicatorGetProcessesRanOnV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator get processes ran on v1 internal server error response has a 4xx status code
func (o *IndicatorGetProcessesRanOnV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this indicator get processes ran on v1 internal server error response has a 5xx status code
func (o *IndicatorGetProcessesRanOnV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this indicator get processes ran on v1 internal server error response a status code equal to that given
func (o *IndicatorGetProcessesRanOnV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the indicator get processes ran on v1 internal server error response
func (o *IndicatorGetProcessesRanOnV1InternalServerError) Code() int {
	return 500
}

func (o *IndicatorGetProcessesRanOnV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1InternalServerError  %+v", 500, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /iocs/queries/indicators/processes/v1][%d] indicatorGetProcessesRanOnV1InternalServerError  %+v", 500, o.Payload)
}

func (o *IndicatorGetProcessesRanOnV1InternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorGetProcessesRanOnV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
