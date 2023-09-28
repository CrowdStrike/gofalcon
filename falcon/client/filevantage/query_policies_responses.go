// Code generated by go-swagger; DO NOT EDIT.

package filevantage

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

// QueryPoliciesReader is a Reader for the QueryPolicies structure.
type QueryPoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryPoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryPoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryPoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryPoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryPoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryPoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /filevantage/queries/policies/v1] queryPolicies", response, response.Code())
	}
}

// NewQueryPoliciesOK creates a QueryPoliciesOK with default headers values
func NewQueryPoliciesOK() *QueryPoliciesOK {
	return &QueryPoliciesOK{}
}

/*
QueryPoliciesOK describes a response with status code 200, with default header values.

OK
*/
type QueryPoliciesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecQueryResponse
}

// IsSuccess returns true when this query policies o k response has a 2xx status code
func (o *QueryPoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query policies o k response has a 3xx status code
func (o *QueryPoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policies o k response has a 4xx status code
func (o *QueryPoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query policies o k response has a 5xx status code
func (o *QueryPoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query policies o k response a status code equal to that given
func (o *QueryPoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query policies o k response
func (o *QueryPoliciesOK) Code() int {
	return 200
}

func (o *QueryPoliciesOK) Error() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesOK  %+v", 200, o.Payload)
}

func (o *QueryPoliciesOK) String() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesOK  %+v", 200, o.Payload)
}

func (o *QueryPoliciesOK) GetPayload() *models.MsaspecQueryResponse {
	return o.Payload
}

func (o *QueryPoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryPoliciesBadRequest creates a QueryPoliciesBadRequest with default headers values
func NewQueryPoliciesBadRequest() *QueryPoliciesBadRequest {
	return &QueryPoliciesBadRequest{}
}

/*
QueryPoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryPoliciesBadRequest struct {

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

// IsSuccess returns true when this query policies bad request response has a 2xx status code
func (o *QueryPoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policies bad request response has a 3xx status code
func (o *QueryPoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policies bad request response has a 4xx status code
func (o *QueryPoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query policies bad request response has a 5xx status code
func (o *QueryPoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query policies bad request response a status code equal to that given
func (o *QueryPoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query policies bad request response
func (o *QueryPoliciesBadRequest) Code() int {
	return 400
}

func (o *QueryPoliciesBadRequest) Error() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryPoliciesBadRequest) String() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryPoliciesBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryPoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryPoliciesForbidden creates a QueryPoliciesForbidden with default headers values
func NewQueryPoliciesForbidden() *QueryPoliciesForbidden {
	return &QueryPoliciesForbidden{}
}

/*
QueryPoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryPoliciesForbidden struct {

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

// IsSuccess returns true when this query policies forbidden response has a 2xx status code
func (o *QueryPoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policies forbidden response has a 3xx status code
func (o *QueryPoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policies forbidden response has a 4xx status code
func (o *QueryPoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query policies forbidden response has a 5xx status code
func (o *QueryPoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query policies forbidden response a status code equal to that given
func (o *QueryPoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query policies forbidden response
func (o *QueryPoliciesForbidden) Code() int {
	return 403
}

func (o *QueryPoliciesForbidden) Error() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *QueryPoliciesForbidden) String() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *QueryPoliciesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryPoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryPoliciesTooManyRequests creates a QueryPoliciesTooManyRequests with default headers values
func NewQueryPoliciesTooManyRequests() *QueryPoliciesTooManyRequests {
	return &QueryPoliciesTooManyRequests{}
}

/*
QueryPoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryPoliciesTooManyRequests struct {

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

// IsSuccess returns true when this query policies too many requests response has a 2xx status code
func (o *QueryPoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policies too many requests response has a 3xx status code
func (o *QueryPoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policies too many requests response has a 4xx status code
func (o *QueryPoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query policies too many requests response has a 5xx status code
func (o *QueryPoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query policies too many requests response a status code equal to that given
func (o *QueryPoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query policies too many requests response
func (o *QueryPoliciesTooManyRequests) Code() int {
	return 429
}

func (o *QueryPoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryPoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryPoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryPoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryPoliciesInternalServerError creates a QueryPoliciesInternalServerError with default headers values
func NewQueryPoliciesInternalServerError() *QueryPoliciesInternalServerError {
	return &QueryPoliciesInternalServerError{}
}

/*
QueryPoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryPoliciesInternalServerError struct {

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

// IsSuccess returns true when this query policies internal server error response has a 2xx status code
func (o *QueryPoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policies internal server error response has a 3xx status code
func (o *QueryPoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policies internal server error response has a 4xx status code
func (o *QueryPoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query policies internal server error response has a 5xx status code
func (o *QueryPoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query policies internal server error response a status code equal to that given
func (o *QueryPoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query policies internal server error response
func (o *QueryPoliciesInternalServerError) Code() int {
	return 500
}

func (o *QueryPoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryPoliciesInternalServerError) String() string {
	return fmt.Sprintf("[GET /filevantage/queries/policies/v1][%d] queryPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryPoliciesInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryPoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
