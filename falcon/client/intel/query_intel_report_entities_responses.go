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

// QueryIntelReportEntitiesReader is a Reader for the QueryIntelReportEntities structure.
type QueryIntelReportEntitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryIntelReportEntitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryIntelReportEntitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryIntelReportEntitiesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryIntelReportEntitiesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryIntelReportEntitiesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryIntelReportEntitiesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /intel/combined/reports/v1] QueryIntelReportEntities", response, response.Code())
	}
}

// NewQueryIntelReportEntitiesOK creates a QueryIntelReportEntitiesOK with default headers values
func NewQueryIntelReportEntitiesOK() *QueryIntelReportEntitiesOK {
	return &QueryIntelReportEntitiesOK{}
}

/*
QueryIntelReportEntitiesOK describes a response with status code 200, with default header values.

OK
*/
type QueryIntelReportEntitiesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainNewsResponse
}

// IsSuccess returns true when this query intel report entities o k response has a 2xx status code
func (o *QueryIntelReportEntitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query intel report entities o k response has a 3xx status code
func (o *QueryIntelReportEntitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel report entities o k response has a 4xx status code
func (o *QueryIntelReportEntitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query intel report entities o k response has a 5xx status code
func (o *QueryIntelReportEntitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel report entities o k response a status code equal to that given
func (o *QueryIntelReportEntitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query intel report entities o k response
func (o *QueryIntelReportEntitiesOK) Code() int {
	return 200
}

func (o *QueryIntelReportEntitiesOK) Error() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesOK  %+v", 200, o.Payload)
}

func (o *QueryIntelReportEntitiesOK) String() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesOK  %+v", 200, o.Payload)
}

func (o *QueryIntelReportEntitiesOK) GetPayload() *models.DomainNewsResponse {
	return o.Payload
}

func (o *QueryIntelReportEntitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainNewsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryIntelReportEntitiesBadRequest creates a QueryIntelReportEntitiesBadRequest with default headers values
func NewQueryIntelReportEntitiesBadRequest() *QueryIntelReportEntitiesBadRequest {
	return &QueryIntelReportEntitiesBadRequest{}
}

/*
QueryIntelReportEntitiesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryIntelReportEntitiesBadRequest struct {

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

// IsSuccess returns true when this query intel report entities bad request response has a 2xx status code
func (o *QueryIntelReportEntitiesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel report entities bad request response has a 3xx status code
func (o *QueryIntelReportEntitiesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel report entities bad request response has a 4xx status code
func (o *QueryIntelReportEntitiesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel report entities bad request response has a 5xx status code
func (o *QueryIntelReportEntitiesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel report entities bad request response a status code equal to that given
func (o *QueryIntelReportEntitiesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query intel report entities bad request response
func (o *QueryIntelReportEntitiesBadRequest) Code() int {
	return 400
}

func (o *QueryIntelReportEntitiesBadRequest) Error() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesBadRequest ", 400)
}

func (o *QueryIntelReportEntitiesBadRequest) String() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesBadRequest ", 400)
}

func (o *QueryIntelReportEntitiesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelReportEntitiesForbidden creates a QueryIntelReportEntitiesForbidden with default headers values
func NewQueryIntelReportEntitiesForbidden() *QueryIntelReportEntitiesForbidden {
	return &QueryIntelReportEntitiesForbidden{}
}

/*
QueryIntelReportEntitiesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryIntelReportEntitiesForbidden struct {

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

// IsSuccess returns true when this query intel report entities forbidden response has a 2xx status code
func (o *QueryIntelReportEntitiesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel report entities forbidden response has a 3xx status code
func (o *QueryIntelReportEntitiesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel report entities forbidden response has a 4xx status code
func (o *QueryIntelReportEntitiesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel report entities forbidden response has a 5xx status code
func (o *QueryIntelReportEntitiesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel report entities forbidden response a status code equal to that given
func (o *QueryIntelReportEntitiesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query intel report entities forbidden response
func (o *QueryIntelReportEntitiesForbidden) Code() int {
	return 403
}

func (o *QueryIntelReportEntitiesForbidden) Error() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryIntelReportEntitiesForbidden) String() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryIntelReportEntitiesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIntelReportEntitiesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelReportEntitiesTooManyRequests creates a QueryIntelReportEntitiesTooManyRequests with default headers values
func NewQueryIntelReportEntitiesTooManyRequests() *QueryIntelReportEntitiesTooManyRequests {
	return &QueryIntelReportEntitiesTooManyRequests{}
}

/*
QueryIntelReportEntitiesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryIntelReportEntitiesTooManyRequests struct {

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

// IsSuccess returns true when this query intel report entities too many requests response has a 2xx status code
func (o *QueryIntelReportEntitiesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel report entities too many requests response has a 3xx status code
func (o *QueryIntelReportEntitiesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel report entities too many requests response has a 4xx status code
func (o *QueryIntelReportEntitiesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel report entities too many requests response has a 5xx status code
func (o *QueryIntelReportEntitiesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel report entities too many requests response a status code equal to that given
func (o *QueryIntelReportEntitiesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query intel report entities too many requests response
func (o *QueryIntelReportEntitiesTooManyRequests) Code() int {
	return 429
}

func (o *QueryIntelReportEntitiesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIntelReportEntitiesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIntelReportEntitiesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIntelReportEntitiesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelReportEntitiesInternalServerError creates a QueryIntelReportEntitiesInternalServerError with default headers values
func NewQueryIntelReportEntitiesInternalServerError() *QueryIntelReportEntitiesInternalServerError {
	return &QueryIntelReportEntitiesInternalServerError{}
}

/*
QueryIntelReportEntitiesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryIntelReportEntitiesInternalServerError struct {

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

// IsSuccess returns true when this query intel report entities internal server error response has a 2xx status code
func (o *QueryIntelReportEntitiesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel report entities internal server error response has a 3xx status code
func (o *QueryIntelReportEntitiesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel report entities internal server error response has a 4xx status code
func (o *QueryIntelReportEntitiesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query intel report entities internal server error response has a 5xx status code
func (o *QueryIntelReportEntitiesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query intel report entities internal server error response a status code equal to that given
func (o *QueryIntelReportEntitiesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query intel report entities internal server error response
func (o *QueryIntelReportEntitiesInternalServerError) Code() int {
	return 500
}

func (o *QueryIntelReportEntitiesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIntelReportEntitiesInternalServerError) String() string {
	return fmt.Sprintf("[GET /intel/combined/reports/v1][%d] queryIntelReportEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIntelReportEntitiesInternalServerError) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryIntelReportEntitiesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
