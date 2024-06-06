// Code generated by go-swagger; DO NOT EDIT.

package discover_iot

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

// QueryIotHostsV2Reader is a Reader for the QueryIotHostsV2 structure.
type QueryIotHostsV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryIotHostsV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryIotHostsV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryIotHostsV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryIotHostsV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryIotHostsV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryIotHostsV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /discover/queries/iot-hosts/v2] query-iot-hostsV2", response, response.Code())
	}
}

// NewQueryIotHostsV2OK creates a QueryIotHostsV2OK with default headers values
func NewQueryIotHostsV2OK() *QueryIotHostsV2OK {
	return &QueryIotHostsV2OK{}
}

/*
QueryIotHostsV2OK describes a response with status code 200, with default header values.

OK
*/
type QueryIotHostsV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainDiscoverAPIResponse
}

// IsSuccess returns true when this query iot hosts v2 o k response has a 2xx status code
func (o *QueryIotHostsV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query iot hosts v2 o k response has a 3xx status code
func (o *QueryIotHostsV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query iot hosts v2 o k response has a 4xx status code
func (o *QueryIotHostsV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query iot hosts v2 o k response has a 5xx status code
func (o *QueryIotHostsV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this query iot hosts v2 o k response a status code equal to that given
func (o *QueryIotHostsV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query iot hosts v2 o k response
func (o *QueryIotHostsV2OK) Code() int {
	return 200
}

func (o *QueryIotHostsV2OK) Error() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2OK  %+v", 200, o.Payload)
}

func (o *QueryIotHostsV2OK) String() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2OK  %+v", 200, o.Payload)
}

func (o *QueryIotHostsV2OK) GetPayload() *models.DomainDiscoverAPIResponse {
	return o.Payload
}

func (o *QueryIotHostsV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainDiscoverAPIResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryIotHostsV2BadRequest creates a QueryIotHostsV2BadRequest with default headers values
func NewQueryIotHostsV2BadRequest() *QueryIotHostsV2BadRequest {
	return &QueryIotHostsV2BadRequest{}
}

/*
QueryIotHostsV2BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryIotHostsV2BadRequest struct {

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

// IsSuccess returns true when this query iot hosts v2 bad request response has a 2xx status code
func (o *QueryIotHostsV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query iot hosts v2 bad request response has a 3xx status code
func (o *QueryIotHostsV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query iot hosts v2 bad request response has a 4xx status code
func (o *QueryIotHostsV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query iot hosts v2 bad request response has a 5xx status code
func (o *QueryIotHostsV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query iot hosts v2 bad request response a status code equal to that given
func (o *QueryIotHostsV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query iot hosts v2 bad request response
func (o *QueryIotHostsV2BadRequest) Code() int {
	return 400
}

func (o *QueryIotHostsV2BadRequest) Error() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2BadRequest  %+v", 400, o.Payload)
}

func (o *QueryIotHostsV2BadRequest) String() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2BadRequest  %+v", 400, o.Payload)
}

func (o *QueryIotHostsV2BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryIotHostsV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIotHostsV2Forbidden creates a QueryIotHostsV2Forbidden with default headers values
func NewQueryIotHostsV2Forbidden() *QueryIotHostsV2Forbidden {
	return &QueryIotHostsV2Forbidden{}
}

/*
QueryIotHostsV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryIotHostsV2Forbidden struct {

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

// IsSuccess returns true when this query iot hosts v2 forbidden response has a 2xx status code
func (o *QueryIotHostsV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query iot hosts v2 forbidden response has a 3xx status code
func (o *QueryIotHostsV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query iot hosts v2 forbidden response has a 4xx status code
func (o *QueryIotHostsV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query iot hosts v2 forbidden response has a 5xx status code
func (o *QueryIotHostsV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query iot hosts v2 forbidden response a status code equal to that given
func (o *QueryIotHostsV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query iot hosts v2 forbidden response
func (o *QueryIotHostsV2Forbidden) Code() int {
	return 403
}

func (o *QueryIotHostsV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2Forbidden  %+v", 403, o.Payload)
}

func (o *QueryIotHostsV2Forbidden) String() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2Forbidden  %+v", 403, o.Payload)
}

func (o *QueryIotHostsV2Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIotHostsV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIotHostsV2TooManyRequests creates a QueryIotHostsV2TooManyRequests with default headers values
func NewQueryIotHostsV2TooManyRequests() *QueryIotHostsV2TooManyRequests {
	return &QueryIotHostsV2TooManyRequests{}
}

/*
QueryIotHostsV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryIotHostsV2TooManyRequests struct {

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

// IsSuccess returns true when this query iot hosts v2 too many requests response has a 2xx status code
func (o *QueryIotHostsV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query iot hosts v2 too many requests response has a 3xx status code
func (o *QueryIotHostsV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query iot hosts v2 too many requests response has a 4xx status code
func (o *QueryIotHostsV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query iot hosts v2 too many requests response has a 5xx status code
func (o *QueryIotHostsV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query iot hosts v2 too many requests response a status code equal to that given
func (o *QueryIotHostsV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query iot hosts v2 too many requests response
func (o *QueryIotHostsV2TooManyRequests) Code() int {
	return 429
}

func (o *QueryIotHostsV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIotHostsV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIotHostsV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIotHostsV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIotHostsV2InternalServerError creates a QueryIotHostsV2InternalServerError with default headers values
func NewQueryIotHostsV2InternalServerError() *QueryIotHostsV2InternalServerError {
	return &QueryIotHostsV2InternalServerError{}
}

/*
QueryIotHostsV2InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryIotHostsV2InternalServerError struct {

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

// IsSuccess returns true when this query iot hosts v2 internal server error response has a 2xx status code
func (o *QueryIotHostsV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query iot hosts v2 internal server error response has a 3xx status code
func (o *QueryIotHostsV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query iot hosts v2 internal server error response has a 4xx status code
func (o *QueryIotHostsV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query iot hosts v2 internal server error response has a 5xx status code
func (o *QueryIotHostsV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query iot hosts v2 internal server error response a status code equal to that given
func (o *QueryIotHostsV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query iot hosts v2 internal server error response
func (o *QueryIotHostsV2InternalServerError) Code() int {
	return 500
}

func (o *QueryIotHostsV2InternalServerError) Error() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2InternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIotHostsV2InternalServerError) String() string {
	return fmt.Sprintf("[GET /discover/queries/iot-hosts/v2][%d] queryIotHostsV2InternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIotHostsV2InternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryIotHostsV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
