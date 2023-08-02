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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// QueryIntelIndicatorEntitiesReader is a Reader for the QueryIntelIndicatorEntities structure.
type QueryIntelIndicatorEntitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryIntelIndicatorEntitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryIntelIndicatorEntitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryIntelIndicatorEntitiesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryIntelIndicatorEntitiesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryIntelIndicatorEntitiesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryIntelIndicatorEntitiesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /intel/combined/indicators/v1] QueryIntelIndicatorEntities", response, response.Code())
	}
}

// NewQueryIntelIndicatorEntitiesOK creates a QueryIntelIndicatorEntitiesOK with default headers values
func NewQueryIntelIndicatorEntitiesOK() *QueryIntelIndicatorEntitiesOK {
	return &QueryIntelIndicatorEntitiesOK{}
}

/*
QueryIntelIndicatorEntitiesOK describes a response with status code 200, with default header values.

OK
*/
type QueryIntelIndicatorEntitiesOK struct {

	/* Provides next page pagination URL. Available only if sorting was done using using _marker field, which is the default one.
	 */
	NextPage string

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainPublicIndicatorsV3Response
}

// IsSuccess returns true when this query intel indicator entities o k response has a 2xx status code
func (o *QueryIntelIndicatorEntitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query intel indicator entities o k response has a 3xx status code
func (o *QueryIntelIndicatorEntitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel indicator entities o k response has a 4xx status code
func (o *QueryIntelIndicatorEntitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query intel indicator entities o k response has a 5xx status code
func (o *QueryIntelIndicatorEntitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel indicator entities o k response a status code equal to that given
func (o *QueryIntelIndicatorEntitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query intel indicator entities o k response
func (o *QueryIntelIndicatorEntitiesOK) Code() int {
	return 200
}

func (o *QueryIntelIndicatorEntitiesOK) Error() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesOK  %+v", 200, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesOK) String() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesOK  %+v", 200, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesOK) GetPayload() *models.DomainPublicIndicatorsV3Response {
	return o.Payload
}

func (o *QueryIntelIndicatorEntitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Next-Page
	hdrNextPage := response.GetHeader("Next-Page")

	if hdrNextPage != "" {
		o.NextPage = hdrNextPage
	}

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

	o.Payload = new(models.DomainPublicIndicatorsV3Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryIntelIndicatorEntitiesBadRequest creates a QueryIntelIndicatorEntitiesBadRequest with default headers values
func NewQueryIntelIndicatorEntitiesBadRequest() *QueryIntelIndicatorEntitiesBadRequest {
	return &QueryIntelIndicatorEntitiesBadRequest{}
}

/*
QueryIntelIndicatorEntitiesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryIntelIndicatorEntitiesBadRequest struct {

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

// IsSuccess returns true when this query intel indicator entities bad request response has a 2xx status code
func (o *QueryIntelIndicatorEntitiesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel indicator entities bad request response has a 3xx status code
func (o *QueryIntelIndicatorEntitiesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel indicator entities bad request response has a 4xx status code
func (o *QueryIntelIndicatorEntitiesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel indicator entities bad request response has a 5xx status code
func (o *QueryIntelIndicatorEntitiesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel indicator entities bad request response a status code equal to that given
func (o *QueryIntelIndicatorEntitiesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query intel indicator entities bad request response
func (o *QueryIntelIndicatorEntitiesBadRequest) Code() int {
	return 400
}

func (o *QueryIntelIndicatorEntitiesBadRequest) Error() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesBadRequest) String() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesBadRequest) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryIntelIndicatorEntitiesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelIndicatorEntitiesForbidden creates a QueryIntelIndicatorEntitiesForbidden with default headers values
func NewQueryIntelIndicatorEntitiesForbidden() *QueryIntelIndicatorEntitiesForbidden {
	return &QueryIntelIndicatorEntitiesForbidden{}
}

/*
QueryIntelIndicatorEntitiesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryIntelIndicatorEntitiesForbidden struct {

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

// IsSuccess returns true when this query intel indicator entities forbidden response has a 2xx status code
func (o *QueryIntelIndicatorEntitiesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel indicator entities forbidden response has a 3xx status code
func (o *QueryIntelIndicatorEntitiesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel indicator entities forbidden response has a 4xx status code
func (o *QueryIntelIndicatorEntitiesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel indicator entities forbidden response has a 5xx status code
func (o *QueryIntelIndicatorEntitiesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel indicator entities forbidden response a status code equal to that given
func (o *QueryIntelIndicatorEntitiesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query intel indicator entities forbidden response
func (o *QueryIntelIndicatorEntitiesForbidden) Code() int {
	return 403
}

func (o *QueryIntelIndicatorEntitiesForbidden) Error() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesForbidden) String() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIntelIndicatorEntitiesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelIndicatorEntitiesTooManyRequests creates a QueryIntelIndicatorEntitiesTooManyRequests with default headers values
func NewQueryIntelIndicatorEntitiesTooManyRequests() *QueryIntelIndicatorEntitiesTooManyRequests {
	return &QueryIntelIndicatorEntitiesTooManyRequests{}
}

/*
QueryIntelIndicatorEntitiesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryIntelIndicatorEntitiesTooManyRequests struct {

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

// IsSuccess returns true when this query intel indicator entities too many requests response has a 2xx status code
func (o *QueryIntelIndicatorEntitiesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel indicator entities too many requests response has a 3xx status code
func (o *QueryIntelIndicatorEntitiesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel indicator entities too many requests response has a 4xx status code
func (o *QueryIntelIndicatorEntitiesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel indicator entities too many requests response has a 5xx status code
func (o *QueryIntelIndicatorEntitiesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel indicator entities too many requests response a status code equal to that given
func (o *QueryIntelIndicatorEntitiesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query intel indicator entities too many requests response
func (o *QueryIntelIndicatorEntitiesTooManyRequests) Code() int {
	return 429
}

func (o *QueryIntelIndicatorEntitiesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIntelIndicatorEntitiesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelIndicatorEntitiesInternalServerError creates a QueryIntelIndicatorEntitiesInternalServerError with default headers values
func NewQueryIntelIndicatorEntitiesInternalServerError() *QueryIntelIndicatorEntitiesInternalServerError {
	return &QueryIntelIndicatorEntitiesInternalServerError{}
}

/*
QueryIntelIndicatorEntitiesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryIntelIndicatorEntitiesInternalServerError struct {

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

// IsSuccess returns true when this query intel indicator entities internal server error response has a 2xx status code
func (o *QueryIntelIndicatorEntitiesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel indicator entities internal server error response has a 3xx status code
func (o *QueryIntelIndicatorEntitiesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel indicator entities internal server error response has a 4xx status code
func (o *QueryIntelIndicatorEntitiesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query intel indicator entities internal server error response has a 5xx status code
func (o *QueryIntelIndicatorEntitiesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query intel indicator entities internal server error response a status code equal to that given
func (o *QueryIntelIndicatorEntitiesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query intel indicator entities internal server error response
func (o *QueryIntelIndicatorEntitiesInternalServerError) Code() int {
	return 500
}

func (o *QueryIntelIndicatorEntitiesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesInternalServerError) String() string {
	return fmt.Sprintf("[GET /intel/combined/indicators/v1][%d] queryIntelIndicatorEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIntelIndicatorEntitiesInternalServerError) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryIntelIndicatorEntitiesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
