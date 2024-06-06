// Code generated by go-swagger; DO NOT EDIT.

package intel

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

// QueryVulnerabilitiesReader is a Reader for the QueryVulnerabilities structure.
type QueryVulnerabilitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryVulnerabilitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryVulnerabilitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewQueryVulnerabilitiesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewQueryVulnerabilitiesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryVulnerabilitiesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryVulnerabilitiesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /intel/queries/vulnerabilities/v1] QueryVulnerabilities", response, response.Code())
	}
}

// NewQueryVulnerabilitiesOK creates a QueryVulnerabilitiesOK with default headers values
func NewQueryVulnerabilitiesOK() *QueryVulnerabilitiesOK {
	return &QueryVulnerabilitiesOK{}
}

/*
QueryVulnerabilitiesOK describes a response with status code 200, with default header values.

OK
*/
type QueryVulnerabilitiesOK struct {

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

// IsSuccess returns true when this query vulnerabilities o k response has a 2xx status code
func (o *QueryVulnerabilitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query vulnerabilities o k response has a 3xx status code
func (o *QueryVulnerabilitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query vulnerabilities o k response has a 4xx status code
func (o *QueryVulnerabilitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query vulnerabilities o k response has a 5xx status code
func (o *QueryVulnerabilitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query vulnerabilities o k response a status code equal to that given
func (o *QueryVulnerabilitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query vulnerabilities o k response
func (o *QueryVulnerabilitiesOK) Code() int {
	return 200
}

func (o *QueryVulnerabilitiesOK) Error() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesOK  %+v", 200, o.Payload)
}

func (o *QueryVulnerabilitiesOK) String() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesOK  %+v", 200, o.Payload)
}

func (o *QueryVulnerabilitiesOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryVulnerabilitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryVulnerabilitiesForbidden creates a QueryVulnerabilitiesForbidden with default headers values
func NewQueryVulnerabilitiesForbidden() *QueryVulnerabilitiesForbidden {
	return &QueryVulnerabilitiesForbidden{}
}

/*
QueryVulnerabilitiesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryVulnerabilitiesForbidden struct {

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

// IsSuccess returns true when this query vulnerabilities forbidden response has a 2xx status code
func (o *QueryVulnerabilitiesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query vulnerabilities forbidden response has a 3xx status code
func (o *QueryVulnerabilitiesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query vulnerabilities forbidden response has a 4xx status code
func (o *QueryVulnerabilitiesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query vulnerabilities forbidden response has a 5xx status code
func (o *QueryVulnerabilitiesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query vulnerabilities forbidden response a status code equal to that given
func (o *QueryVulnerabilitiesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query vulnerabilities forbidden response
func (o *QueryVulnerabilitiesForbidden) Code() int {
	return 403
}

func (o *QueryVulnerabilitiesForbidden) Error() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryVulnerabilitiesForbidden) String() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryVulnerabilitiesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryVulnerabilitiesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryVulnerabilitiesNotFound creates a QueryVulnerabilitiesNotFound with default headers values
func NewQueryVulnerabilitiesNotFound() *QueryVulnerabilitiesNotFound {
	return &QueryVulnerabilitiesNotFound{}
}

/*
QueryVulnerabilitiesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type QueryVulnerabilitiesNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this query vulnerabilities not found response has a 2xx status code
func (o *QueryVulnerabilitiesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query vulnerabilities not found response has a 3xx status code
func (o *QueryVulnerabilitiesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query vulnerabilities not found response has a 4xx status code
func (o *QueryVulnerabilitiesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this query vulnerabilities not found response has a 5xx status code
func (o *QueryVulnerabilitiesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this query vulnerabilities not found response a status code equal to that given
func (o *QueryVulnerabilitiesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the query vulnerabilities not found response
func (o *QueryVulnerabilitiesNotFound) Code() int {
	return 404
}

func (o *QueryVulnerabilitiesNotFound) Error() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesNotFound  %+v", 404, o.Payload)
}

func (o *QueryVulnerabilitiesNotFound) String() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesNotFound  %+v", 404, o.Payload)
}

func (o *QueryVulnerabilitiesNotFound) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryVulnerabilitiesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryVulnerabilitiesTooManyRequests creates a QueryVulnerabilitiesTooManyRequests with default headers values
func NewQueryVulnerabilitiesTooManyRequests() *QueryVulnerabilitiesTooManyRequests {
	return &QueryVulnerabilitiesTooManyRequests{}
}

/*
QueryVulnerabilitiesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryVulnerabilitiesTooManyRequests struct {

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

// IsSuccess returns true when this query vulnerabilities too many requests response has a 2xx status code
func (o *QueryVulnerabilitiesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query vulnerabilities too many requests response has a 3xx status code
func (o *QueryVulnerabilitiesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query vulnerabilities too many requests response has a 4xx status code
func (o *QueryVulnerabilitiesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query vulnerabilities too many requests response has a 5xx status code
func (o *QueryVulnerabilitiesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query vulnerabilities too many requests response a status code equal to that given
func (o *QueryVulnerabilitiesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query vulnerabilities too many requests response
func (o *QueryVulnerabilitiesTooManyRequests) Code() int {
	return 429
}

func (o *QueryVulnerabilitiesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryVulnerabilitiesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryVulnerabilitiesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryVulnerabilitiesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryVulnerabilitiesInternalServerError creates a QueryVulnerabilitiesInternalServerError with default headers values
func NewQueryVulnerabilitiesInternalServerError() *QueryVulnerabilitiesInternalServerError {
	return &QueryVulnerabilitiesInternalServerError{}
}

/*
QueryVulnerabilitiesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryVulnerabilitiesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this query vulnerabilities internal server error response has a 2xx status code
func (o *QueryVulnerabilitiesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query vulnerabilities internal server error response has a 3xx status code
func (o *QueryVulnerabilitiesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query vulnerabilities internal server error response has a 4xx status code
func (o *QueryVulnerabilitiesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query vulnerabilities internal server error response has a 5xx status code
func (o *QueryVulnerabilitiesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query vulnerabilities internal server error response a status code equal to that given
func (o *QueryVulnerabilitiesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query vulnerabilities internal server error response
func (o *QueryVulnerabilitiesInternalServerError) Code() int {
	return 500
}

func (o *QueryVulnerabilitiesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryVulnerabilitiesInternalServerError) String() string {
	return fmt.Sprintf("[GET /intel/queries/vulnerabilities/v1][%d] queryVulnerabilitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryVulnerabilitiesInternalServerError) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryVulnerabilitiesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
