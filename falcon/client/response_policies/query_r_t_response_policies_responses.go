// Code generated by go-swagger; DO NOT EDIT.

package response_policies

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

// QueryRTResponsePoliciesReader is a Reader for the QueryRTResponsePolicies structure.
type QueryRTResponsePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryRTResponsePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryRTResponsePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryRTResponsePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryRTResponsePoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryRTResponsePoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryRTResponsePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /policy/queries/response/v1] queryRTResponsePolicies", response, response.Code())
	}
}

// NewQueryRTResponsePoliciesOK creates a QueryRTResponsePoliciesOK with default headers values
func NewQueryRTResponsePoliciesOK() *QueryRTResponsePoliciesOK {
	return &QueryRTResponsePoliciesOK{}
}

/*
QueryRTResponsePoliciesOK describes a response with status code 200, with default header values.

OK
*/
type QueryRTResponsePoliciesOK struct {

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

// IsSuccess returns true when this query r t response policies o k response has a 2xx status code
func (o *QueryRTResponsePoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query r t response policies o k response has a 3xx status code
func (o *QueryRTResponsePoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query r t response policies o k response has a 4xx status code
func (o *QueryRTResponsePoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query r t response policies o k response has a 5xx status code
func (o *QueryRTResponsePoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query r t response policies o k response a status code equal to that given
func (o *QueryRTResponsePoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query r t response policies o k response
func (o *QueryRTResponsePoliciesOK) Code() int {
	return 200
}

func (o *QueryRTResponsePoliciesOK) Error() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesOK  %+v", 200, o.Payload)
}

func (o *QueryRTResponsePoliciesOK) String() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesOK  %+v", 200, o.Payload)
}

func (o *QueryRTResponsePoliciesOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryRTResponsePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRTResponsePoliciesBadRequest creates a QueryRTResponsePoliciesBadRequest with default headers values
func NewQueryRTResponsePoliciesBadRequest() *QueryRTResponsePoliciesBadRequest {
	return &QueryRTResponsePoliciesBadRequest{}
}

/*
QueryRTResponsePoliciesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryRTResponsePoliciesBadRequest struct {

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

// IsSuccess returns true when this query r t response policies bad request response has a 2xx status code
func (o *QueryRTResponsePoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query r t response policies bad request response has a 3xx status code
func (o *QueryRTResponsePoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query r t response policies bad request response has a 4xx status code
func (o *QueryRTResponsePoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query r t response policies bad request response has a 5xx status code
func (o *QueryRTResponsePoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query r t response policies bad request response a status code equal to that given
func (o *QueryRTResponsePoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query r t response policies bad request response
func (o *QueryRTResponsePoliciesBadRequest) Code() int {
	return 400
}

func (o *QueryRTResponsePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryRTResponsePoliciesBadRequest) String() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryRTResponsePoliciesBadRequest) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryRTResponsePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRTResponsePoliciesForbidden creates a QueryRTResponsePoliciesForbidden with default headers values
func NewQueryRTResponsePoliciesForbidden() *QueryRTResponsePoliciesForbidden {
	return &QueryRTResponsePoliciesForbidden{}
}

/*
QueryRTResponsePoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryRTResponsePoliciesForbidden struct {

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

// IsSuccess returns true when this query r t response policies forbidden response has a 2xx status code
func (o *QueryRTResponsePoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query r t response policies forbidden response has a 3xx status code
func (o *QueryRTResponsePoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query r t response policies forbidden response has a 4xx status code
func (o *QueryRTResponsePoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query r t response policies forbidden response has a 5xx status code
func (o *QueryRTResponsePoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query r t response policies forbidden response a status code equal to that given
func (o *QueryRTResponsePoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query r t response policies forbidden response
func (o *QueryRTResponsePoliciesForbidden) Code() int {
	return 403
}

func (o *QueryRTResponsePoliciesForbidden) Error() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *QueryRTResponsePoliciesForbidden) String() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesForbidden  %+v", 403, o.Payload)
}

func (o *QueryRTResponsePoliciesForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *QueryRTResponsePoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRTResponsePoliciesTooManyRequests creates a QueryRTResponsePoliciesTooManyRequests with default headers values
func NewQueryRTResponsePoliciesTooManyRequests() *QueryRTResponsePoliciesTooManyRequests {
	return &QueryRTResponsePoliciesTooManyRequests{}
}

/*
QueryRTResponsePoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryRTResponsePoliciesTooManyRequests struct {

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

// IsSuccess returns true when this query r t response policies too many requests response has a 2xx status code
func (o *QueryRTResponsePoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query r t response policies too many requests response has a 3xx status code
func (o *QueryRTResponsePoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query r t response policies too many requests response has a 4xx status code
func (o *QueryRTResponsePoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query r t response policies too many requests response has a 5xx status code
func (o *QueryRTResponsePoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query r t response policies too many requests response a status code equal to that given
func (o *QueryRTResponsePoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query r t response policies too many requests response
func (o *QueryRTResponsePoliciesTooManyRequests) Code() int {
	return 429
}

func (o *QueryRTResponsePoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryRTResponsePoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryRTResponsePoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryRTResponsePoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRTResponsePoliciesInternalServerError creates a QueryRTResponsePoliciesInternalServerError with default headers values
func NewQueryRTResponsePoliciesInternalServerError() *QueryRTResponsePoliciesInternalServerError {
	return &QueryRTResponsePoliciesInternalServerError{}
}

/*
QueryRTResponsePoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryRTResponsePoliciesInternalServerError struct {

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

// IsSuccess returns true when this query r t response policies internal server error response has a 2xx status code
func (o *QueryRTResponsePoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query r t response policies internal server error response has a 3xx status code
func (o *QueryRTResponsePoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query r t response policies internal server error response has a 4xx status code
func (o *QueryRTResponsePoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query r t response policies internal server error response has a 5xx status code
func (o *QueryRTResponsePoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query r t response policies internal server error response a status code equal to that given
func (o *QueryRTResponsePoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query r t response policies internal server error response
func (o *QueryRTResponsePoliciesInternalServerError) Code() int {
	return 500
}

func (o *QueryRTResponsePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryRTResponsePoliciesInternalServerError) String() string {
	return fmt.Sprintf("[GET /policy/queries/response/v1][%d] queryRTResponsePoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryRTResponsePoliciesInternalServerError) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryRTResponsePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
