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

// QueryIntelActorEntitiesReader is a Reader for the QueryIntelActorEntities structure.
type QueryIntelActorEntitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryIntelActorEntitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryIntelActorEntitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryIntelActorEntitiesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryIntelActorEntitiesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryIntelActorEntitiesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryIntelActorEntitiesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /intel/combined/actors/v1] QueryIntelActorEntities", response, response.Code())
	}
}

// NewQueryIntelActorEntitiesOK creates a QueryIntelActorEntitiesOK with default headers values
func NewQueryIntelActorEntitiesOK() *QueryIntelActorEntitiesOK {
	return &QueryIntelActorEntitiesOK{}
}

/* QueryIntelActorEntitiesOK describes a response with status code 200, with default header values.

OK
*/
type QueryIntelActorEntitiesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainActorsResponse
}

// IsSuccess returns true when this query intel actor entities o k response has a 2xx status code
func (o *QueryIntelActorEntitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query intel actor entities o k response has a 3xx status code
func (o *QueryIntelActorEntitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel actor entities o k response has a 4xx status code
func (o *QueryIntelActorEntitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query intel actor entities o k response has a 5xx status code
func (o *QueryIntelActorEntitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel actor entities o k response a status code equal to that given
func (o *QueryIntelActorEntitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query intel actor entities o k response
func (o *QueryIntelActorEntitiesOK) Code() int {
	return 200
}

func (o *QueryIntelActorEntitiesOK) Error() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesOK  %+v", 200, o.Payload)
}

func (o *QueryIntelActorEntitiesOK) String() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesOK  %+v", 200, o.Payload)
}

func (o *QueryIntelActorEntitiesOK) GetPayload() *models.DomainActorsResponse {
	return o.Payload
}

func (o *QueryIntelActorEntitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainActorsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryIntelActorEntitiesBadRequest creates a QueryIntelActorEntitiesBadRequest with default headers values
func NewQueryIntelActorEntitiesBadRequest() *QueryIntelActorEntitiesBadRequest {
	return &QueryIntelActorEntitiesBadRequest{}
}

/* QueryIntelActorEntitiesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryIntelActorEntitiesBadRequest struct {

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

// IsSuccess returns true when this query intel actor entities bad request response has a 2xx status code
func (o *QueryIntelActorEntitiesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel actor entities bad request response has a 3xx status code
func (o *QueryIntelActorEntitiesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel actor entities bad request response has a 4xx status code
func (o *QueryIntelActorEntitiesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel actor entities bad request response has a 5xx status code
func (o *QueryIntelActorEntitiesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel actor entities bad request response a status code equal to that given
func (o *QueryIntelActorEntitiesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query intel actor entities bad request response
func (o *QueryIntelActorEntitiesBadRequest) Code() int {
	return 400
}

func (o *QueryIntelActorEntitiesBadRequest) Error() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryIntelActorEntitiesBadRequest) String() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryIntelActorEntitiesBadRequest) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryIntelActorEntitiesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelActorEntitiesForbidden creates a QueryIntelActorEntitiesForbidden with default headers values
func NewQueryIntelActorEntitiesForbidden() *QueryIntelActorEntitiesForbidden {
	return &QueryIntelActorEntitiesForbidden{}
}

/* QueryIntelActorEntitiesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryIntelActorEntitiesForbidden struct {

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

// IsSuccess returns true when this query intel actor entities forbidden response has a 2xx status code
func (o *QueryIntelActorEntitiesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel actor entities forbidden response has a 3xx status code
func (o *QueryIntelActorEntitiesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel actor entities forbidden response has a 4xx status code
func (o *QueryIntelActorEntitiesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel actor entities forbidden response has a 5xx status code
func (o *QueryIntelActorEntitiesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel actor entities forbidden response a status code equal to that given
func (o *QueryIntelActorEntitiesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query intel actor entities forbidden response
func (o *QueryIntelActorEntitiesForbidden) Code() int {
	return 403
}

func (o *QueryIntelActorEntitiesForbidden) Error() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryIntelActorEntitiesForbidden) String() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *QueryIntelActorEntitiesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIntelActorEntitiesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelActorEntitiesTooManyRequests creates a QueryIntelActorEntitiesTooManyRequests with default headers values
func NewQueryIntelActorEntitiesTooManyRequests() *QueryIntelActorEntitiesTooManyRequests {
	return &QueryIntelActorEntitiesTooManyRequests{}
}

/* QueryIntelActorEntitiesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryIntelActorEntitiesTooManyRequests struct {

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

// IsSuccess returns true when this query intel actor entities too many requests response has a 2xx status code
func (o *QueryIntelActorEntitiesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel actor entities too many requests response has a 3xx status code
func (o *QueryIntelActorEntitiesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel actor entities too many requests response has a 4xx status code
func (o *QueryIntelActorEntitiesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query intel actor entities too many requests response has a 5xx status code
func (o *QueryIntelActorEntitiesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query intel actor entities too many requests response a status code equal to that given
func (o *QueryIntelActorEntitiesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query intel actor entities too many requests response
func (o *QueryIntelActorEntitiesTooManyRequests) Code() int {
	return 429
}

func (o *QueryIntelActorEntitiesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIntelActorEntitiesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryIntelActorEntitiesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryIntelActorEntitiesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryIntelActorEntitiesInternalServerError creates a QueryIntelActorEntitiesInternalServerError with default headers values
func NewQueryIntelActorEntitiesInternalServerError() *QueryIntelActorEntitiesInternalServerError {
	return &QueryIntelActorEntitiesInternalServerError{}
}

/* QueryIntelActorEntitiesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryIntelActorEntitiesInternalServerError struct {

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

// IsSuccess returns true when this query intel actor entities internal server error response has a 2xx status code
func (o *QueryIntelActorEntitiesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query intel actor entities internal server error response has a 3xx status code
func (o *QueryIntelActorEntitiesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query intel actor entities internal server error response has a 4xx status code
func (o *QueryIntelActorEntitiesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query intel actor entities internal server error response has a 5xx status code
func (o *QueryIntelActorEntitiesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query intel actor entities internal server error response a status code equal to that given
func (o *QueryIntelActorEntitiesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query intel actor entities internal server error response
func (o *QueryIntelActorEntitiesInternalServerError) Code() int {
	return 500
}

func (o *QueryIntelActorEntitiesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIntelActorEntitiesInternalServerError) String() string {
	return fmt.Sprintf("[GET /intel/combined/actors/v1][%d] queryIntelActorEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryIntelActorEntitiesInternalServerError) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryIntelActorEntitiesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
