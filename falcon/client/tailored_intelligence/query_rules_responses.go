// Code generated by go-swagger; DO NOT EDIT.

package tailored_intelligence

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

// QueryRulesReader is a Reader for the QueryRules structure.
type QueryRulesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryRulesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryRulesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryRulesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryRulesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryRulesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryRulesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewQueryRulesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewQueryRulesOK creates a QueryRulesOK with default headers values
func NewQueryRulesOK() *QueryRulesOK {
	return &QueryRulesOK{}
}

/*
QueryRulesOK describes a response with status code 200, with default header values.

OK
*/
type QueryRulesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainQueryResponse
}

// IsSuccess returns true when this query rules o k response has a 2xx status code
func (o *QueryRulesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query rules o k response has a 3xx status code
func (o *QueryRulesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rules o k response has a 4xx status code
func (o *QueryRulesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query rules o k response has a 5xx status code
func (o *QueryRulesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query rules o k response a status code equal to that given
func (o *QueryRulesOK) IsCode(code int) bool {
	return code == 200
}

func (o *QueryRulesOK) Error() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesOK  %+v", 200, o.Payload)
}

func (o *QueryRulesOK) String() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesOK  %+v", 200, o.Payload)
}

func (o *QueryRulesOK) GetPayload() *models.DomainQueryResponse {
	return o.Payload
}

func (o *QueryRulesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryRulesBadRequest creates a QueryRulesBadRequest with default headers values
func NewQueryRulesBadRequest() *QueryRulesBadRequest {
	return &QueryRulesBadRequest{}
}

/*
QueryRulesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryRulesBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainQueryResponse
}

// IsSuccess returns true when this query rules bad request response has a 2xx status code
func (o *QueryRulesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rules bad request response has a 3xx status code
func (o *QueryRulesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rules bad request response has a 4xx status code
func (o *QueryRulesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query rules bad request response has a 5xx status code
func (o *QueryRulesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query rules bad request response a status code equal to that given
func (o *QueryRulesBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *QueryRulesBadRequest) Error() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryRulesBadRequest) String() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesBadRequest  %+v", 400, o.Payload)
}

func (o *QueryRulesBadRequest) GetPayload() *models.DomainQueryResponse {
	return o.Payload
}

func (o *QueryRulesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryRulesForbidden creates a QueryRulesForbidden with default headers values
func NewQueryRulesForbidden() *QueryRulesForbidden {
	return &QueryRulesForbidden{}
}

/*
QueryRulesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryRulesForbidden struct {

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

// IsSuccess returns true when this query rules forbidden response has a 2xx status code
func (o *QueryRulesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rules forbidden response has a 3xx status code
func (o *QueryRulesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rules forbidden response has a 4xx status code
func (o *QueryRulesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query rules forbidden response has a 5xx status code
func (o *QueryRulesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query rules forbidden response a status code equal to that given
func (o *QueryRulesForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *QueryRulesForbidden) Error() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesForbidden ", 403)
}

func (o *QueryRulesForbidden) String() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesForbidden ", 403)
}

func (o *QueryRulesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRulesTooManyRequests creates a QueryRulesTooManyRequests with default headers values
func NewQueryRulesTooManyRequests() *QueryRulesTooManyRequests {
	return &QueryRulesTooManyRequests{}
}

/*
QueryRulesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryRulesTooManyRequests struct {

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

// IsSuccess returns true when this query rules too many requests response has a 2xx status code
func (o *QueryRulesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rules too many requests response has a 3xx status code
func (o *QueryRulesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rules too many requests response has a 4xx status code
func (o *QueryRulesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query rules too many requests response has a 5xx status code
func (o *QueryRulesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query rules too many requests response a status code equal to that given
func (o *QueryRulesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *QueryRulesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryRulesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryRulesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryRulesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryRulesInternalServerError creates a QueryRulesInternalServerError with default headers values
func NewQueryRulesInternalServerError() *QueryRulesInternalServerError {
	return &QueryRulesInternalServerError{}
}

/*
QueryRulesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryRulesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainQueryResponse
}

// IsSuccess returns true when this query rules internal server error response has a 2xx status code
func (o *QueryRulesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query rules internal server error response has a 3xx status code
func (o *QueryRulesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query rules internal server error response has a 4xx status code
func (o *QueryRulesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query rules internal server error response has a 5xx status code
func (o *QueryRulesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query rules internal server error response a status code equal to that given
func (o *QueryRulesInternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *QueryRulesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryRulesInternalServerError) String() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] queryRulesInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryRulesInternalServerError) GetPayload() *models.DomainQueryResponse {
	return o.Payload
}

func (o *QueryRulesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryRulesDefault creates a QueryRulesDefault with default headers values
func NewQueryRulesDefault(code int) *QueryRulesDefault {
	return &QueryRulesDefault{
		_statusCode: code,
	}
}

/*
QueryRulesDefault describes a response with status code -1, with default header values.

OK
*/
type QueryRulesDefault struct {
	_statusCode int

	Payload *models.DomainQueryResponse
}

// Code gets the status code for the query rules default response
func (o *QueryRulesDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this query rules default response has a 2xx status code
func (o *QueryRulesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this query rules default response has a 3xx status code
func (o *QueryRulesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this query rules default response has a 4xx status code
func (o *QueryRulesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this query rules default response has a 5xx status code
func (o *QueryRulesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this query rules default response a status code equal to that given
func (o *QueryRulesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *QueryRulesDefault) Error() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] QueryRules default  %+v", o._statusCode, o.Payload)
}

func (o *QueryRulesDefault) String() string {
	return fmt.Sprintf("[GET /ti/rules/queries/rules/v2][%d] QueryRules default  %+v", o._statusCode, o.Payload)
}

func (o *QueryRulesDefault) GetPayload() *models.DomainQueryResponse {
	return o.Payload
}

func (o *QueryRulesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DomainQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
