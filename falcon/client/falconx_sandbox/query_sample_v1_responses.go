// Code generated by go-swagger; DO NOT EDIT.

package falconx_sandbox

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

// QuerySampleV1Reader is a Reader for the QuerySampleV1 structure.
type QuerySampleV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QuerySampleV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQuerySampleV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQuerySampleV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQuerySampleV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQuerySampleV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQuerySampleV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /samples/queries/samples/GET/v1] QuerySampleV1", response, response.Code())
	}
}

// NewQuerySampleV1OK creates a QuerySampleV1OK with default headers values
func NewQuerySampleV1OK() *QuerySampleV1OK {
	return &QuerySampleV1OK{}
}

/* QuerySampleV1OK describes a response with status code 200, with default header values.

OK
*/
type QuerySampleV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this query sample v1 o k response has a 2xx status code
func (o *QuerySampleV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query sample v1 o k response has a 3xx status code
func (o *QuerySampleV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query sample v1 o k response has a 4xx status code
func (o *QuerySampleV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query sample v1 o k response has a 5xx status code
func (o *QuerySampleV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this query sample v1 o k response a status code equal to that given
func (o *QuerySampleV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query sample v1 o k response
func (o *QuerySampleV1OK) Code() int {
	return 200
}

func (o *QuerySampleV1OK) Error() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1OK  %+v", 200, o.Payload)
}

func (o *QuerySampleV1OK) String() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1OK  %+v", 200, o.Payload)
}

func (o *QuerySampleV1OK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QuerySampleV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQuerySampleV1BadRequest creates a QuerySampleV1BadRequest with default headers values
func NewQuerySampleV1BadRequest() *QuerySampleV1BadRequest {
	return &QuerySampleV1BadRequest{}
}

/* QuerySampleV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QuerySampleV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this query sample v1 bad request response has a 2xx status code
func (o *QuerySampleV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query sample v1 bad request response has a 3xx status code
func (o *QuerySampleV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query sample v1 bad request response has a 4xx status code
func (o *QuerySampleV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query sample v1 bad request response has a 5xx status code
func (o *QuerySampleV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query sample v1 bad request response a status code equal to that given
func (o *QuerySampleV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query sample v1 bad request response
func (o *QuerySampleV1BadRequest) Code() int {
	return 400
}

func (o *QuerySampleV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1BadRequest  %+v", 400, o.Payload)
}

func (o *QuerySampleV1BadRequest) String() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1BadRequest  %+v", 400, o.Payload)
}

func (o *QuerySampleV1BadRequest) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QuerySampleV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQuerySampleV1Forbidden creates a QuerySampleV1Forbidden with default headers values
func NewQuerySampleV1Forbidden() *QuerySampleV1Forbidden {
	return &QuerySampleV1Forbidden{}
}

/* QuerySampleV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QuerySampleV1Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this query sample v1 forbidden response has a 2xx status code
func (o *QuerySampleV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query sample v1 forbidden response has a 3xx status code
func (o *QuerySampleV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query sample v1 forbidden response has a 4xx status code
func (o *QuerySampleV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query sample v1 forbidden response has a 5xx status code
func (o *QuerySampleV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query sample v1 forbidden response a status code equal to that given
func (o *QuerySampleV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query sample v1 forbidden response
func (o *QuerySampleV1Forbidden) Code() int {
	return 403
}

func (o *QuerySampleV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1Forbidden  %+v", 403, o.Payload)
}

func (o *QuerySampleV1Forbidden) String() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1Forbidden  %+v", 403, o.Payload)
}

func (o *QuerySampleV1Forbidden) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QuerySampleV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQuerySampleV1TooManyRequests creates a QuerySampleV1TooManyRequests with default headers values
func NewQuerySampleV1TooManyRequests() *QuerySampleV1TooManyRequests {
	return &QuerySampleV1TooManyRequests{}
}

/* QuerySampleV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QuerySampleV1TooManyRequests struct {

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

// IsSuccess returns true when this query sample v1 too many requests response has a 2xx status code
func (o *QuerySampleV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query sample v1 too many requests response has a 3xx status code
func (o *QuerySampleV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query sample v1 too many requests response has a 4xx status code
func (o *QuerySampleV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query sample v1 too many requests response has a 5xx status code
func (o *QuerySampleV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query sample v1 too many requests response a status code equal to that given
func (o *QuerySampleV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query sample v1 too many requests response
func (o *QuerySampleV1TooManyRequests) Code() int {
	return 429
}

func (o *QuerySampleV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *QuerySampleV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *QuerySampleV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QuerySampleV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQuerySampleV1InternalServerError creates a QuerySampleV1InternalServerError with default headers values
func NewQuerySampleV1InternalServerError() *QuerySampleV1InternalServerError {
	return &QuerySampleV1InternalServerError{}
}

/* QuerySampleV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QuerySampleV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this query sample v1 internal server error response has a 2xx status code
func (o *QuerySampleV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query sample v1 internal server error response has a 3xx status code
func (o *QuerySampleV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query sample v1 internal server error response has a 4xx status code
func (o *QuerySampleV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query sample v1 internal server error response has a 5xx status code
func (o *QuerySampleV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query sample v1 internal server error response a status code equal to that given
func (o *QuerySampleV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query sample v1 internal server error response
func (o *QuerySampleV1InternalServerError) Code() int {
	return 500
}

func (o *QuerySampleV1InternalServerError) Error() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1InternalServerError  %+v", 500, o.Payload)
}

func (o *QuerySampleV1InternalServerError) String() string {
	return fmt.Sprintf("[POST /samples/queries/samples/GET/v1][%d] querySampleV1InternalServerError  %+v", 500, o.Payload)
}

func (o *QuerySampleV1InternalServerError) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QuerySampleV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
