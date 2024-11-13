// Code generated by go-swagger; DO NOT EDIT.

package humio_auth_proxy

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

// StopSearchV1Reader is a Reader for the StopSearchV1 structure.
type StopSearchV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *StopSearchV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewStopSearchV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewStopSearchV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewStopSearchV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewStopSearchV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewStopSearchV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}] StopSearchV1", response, response.Code())
	}
}

// NewStopSearchV1OK creates a StopSearchV1OK with default headers values
func NewStopSearchV1OK() *StopSearchV1OK {
	return &StopSearchV1OK{}
}

/*
StopSearchV1OK describes a response with status code 200, with default header values.

Search has been stopped
*/
type StopSearchV1OK struct {

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

// IsSuccess returns true when this stop search v1 o k response has a 2xx status code
func (o *StopSearchV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this stop search v1 o k response has a 3xx status code
func (o *StopSearchV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this stop search v1 o k response has a 4xx status code
func (o *StopSearchV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this stop search v1 o k response has a 5xx status code
func (o *StopSearchV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this stop search v1 o k response a status code equal to that given
func (o *StopSearchV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the stop search v1 o k response
func (o *StopSearchV1OK) Code() int {
	return 200
}

func (o *StopSearchV1OK) Error() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1OK ", 200)
}

func (o *StopSearchV1OK) String() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1OK ", 200)
}

func (o *StopSearchV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewStopSearchV1Unauthorized creates a StopSearchV1Unauthorized with default headers values
func NewStopSearchV1Unauthorized() *StopSearchV1Unauthorized {
	return &StopSearchV1Unauthorized{}
}

/*
StopSearchV1Unauthorized describes a response with status code 401, with default header values.

Requestor is not authorized
*/
type StopSearchV1Unauthorized struct {

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

// IsSuccess returns true when this stop search v1 unauthorized response has a 2xx status code
func (o *StopSearchV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this stop search v1 unauthorized response has a 3xx status code
func (o *StopSearchV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this stop search v1 unauthorized response has a 4xx status code
func (o *StopSearchV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this stop search v1 unauthorized response has a 5xx status code
func (o *StopSearchV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this stop search v1 unauthorized response a status code equal to that given
func (o *StopSearchV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the stop search v1 unauthorized response
func (o *StopSearchV1Unauthorized) Code() int {
	return 401
}

func (o *StopSearchV1Unauthorized) Error() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1Unauthorized  %+v", 401, o.Payload)
}

func (o *StopSearchV1Unauthorized) String() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1Unauthorized  %+v", 401, o.Payload)
}

func (o *StopSearchV1Unauthorized) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *StopSearchV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewStopSearchV1Forbidden creates a StopSearchV1Forbidden with default headers values
func NewStopSearchV1Forbidden() *StopSearchV1Forbidden {
	return &StopSearchV1Forbidden{}
}

/*
StopSearchV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type StopSearchV1Forbidden struct {

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

// IsSuccess returns true when this stop search v1 forbidden response has a 2xx status code
func (o *StopSearchV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this stop search v1 forbidden response has a 3xx status code
func (o *StopSearchV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this stop search v1 forbidden response has a 4xx status code
func (o *StopSearchV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this stop search v1 forbidden response has a 5xx status code
func (o *StopSearchV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this stop search v1 forbidden response a status code equal to that given
func (o *StopSearchV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the stop search v1 forbidden response
func (o *StopSearchV1Forbidden) Code() int {
	return 403
}

func (o *StopSearchV1Forbidden) Error() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1Forbidden  %+v", 403, o.Payload)
}

func (o *StopSearchV1Forbidden) String() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1Forbidden  %+v", 403, o.Payload)
}

func (o *StopSearchV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *StopSearchV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewStopSearchV1TooManyRequests creates a StopSearchV1TooManyRequests with default headers values
func NewStopSearchV1TooManyRequests() *StopSearchV1TooManyRequests {
	return &StopSearchV1TooManyRequests{}
}

/*
StopSearchV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type StopSearchV1TooManyRequests struct {

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

// IsSuccess returns true when this stop search v1 too many requests response has a 2xx status code
func (o *StopSearchV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this stop search v1 too many requests response has a 3xx status code
func (o *StopSearchV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this stop search v1 too many requests response has a 4xx status code
func (o *StopSearchV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this stop search v1 too many requests response has a 5xx status code
func (o *StopSearchV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this stop search v1 too many requests response a status code equal to that given
func (o *StopSearchV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the stop search v1 too many requests response
func (o *StopSearchV1TooManyRequests) Code() int {
	return 429
}

func (o *StopSearchV1TooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *StopSearchV1TooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *StopSearchV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *StopSearchV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewStopSearchV1InternalServerError creates a StopSearchV1InternalServerError with default headers values
func NewStopSearchV1InternalServerError() *StopSearchV1InternalServerError {
	return &StopSearchV1InternalServerError{}
}

/*
StopSearchV1InternalServerError describes a response with status code 500, with default header values.

Unexpected error occurred
*/
type StopSearchV1InternalServerError struct {

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

// IsSuccess returns true when this stop search v1 internal server error response has a 2xx status code
func (o *StopSearchV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this stop search v1 internal server error response has a 3xx status code
func (o *StopSearchV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this stop search v1 internal server error response has a 4xx status code
func (o *StopSearchV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this stop search v1 internal server error response has a 5xx status code
func (o *StopSearchV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this stop search v1 internal server error response a status code equal to that given
func (o *StopSearchV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the stop search v1 internal server error response
func (o *StopSearchV1InternalServerError) Code() int {
	return 500
}

func (o *StopSearchV1InternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1InternalServerError  %+v", 500, o.Payload)
}

func (o *StopSearchV1InternalServerError) String() string {
	return fmt.Sprintf("[DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}][%d] stopSearchV1InternalServerError  %+v", 500, o.Payload)
}

func (o *StopSearchV1InternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *StopSearchV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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