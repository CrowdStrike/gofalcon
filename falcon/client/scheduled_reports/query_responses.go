// Code generated by go-swagger; DO NOT EDIT.

package scheduled_reports

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

// QueryReader is a Reader for the Query structure.
type QueryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /reports/queries/scheduled-reports/v1] Query", response, response.Code())
	}
}

// NewQueryOK creates a QueryOK with default headers values
func NewQueryOK() *QueryOK {
	return &QueryOK{}
}

/*
QueryOK describes a response with status code 200, with default header values.

OK
*/
type QueryOK struct {

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

// IsSuccess returns true when this query o k response has a 2xx status code
func (o *QueryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query o k response has a 3xx status code
func (o *QueryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query o k response has a 4xx status code
func (o *QueryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query o k response has a 5xx status code
func (o *QueryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query o k response a status code equal to that given
func (o *QueryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query o k response
func (o *QueryOK) Code() int {
	return 200
}

func (o *QueryOK) Error() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryOK  %+v", 200, o.Payload)
}

func (o *QueryOK) String() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryOK  %+v", 200, o.Payload)
}

func (o *QueryOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryBadRequest creates a QueryBadRequest with default headers values
func NewQueryBadRequest() *QueryBadRequest {
	return &QueryBadRequest{}
}

/*
QueryBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryBadRequest struct {

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

// IsSuccess returns true when this query bad request response has a 2xx status code
func (o *QueryBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query bad request response has a 3xx status code
func (o *QueryBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query bad request response has a 4xx status code
func (o *QueryBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query bad request response has a 5xx status code
func (o *QueryBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query bad request response a status code equal to that given
func (o *QueryBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query bad request response
func (o *QueryBadRequest) Code() int {
	return 400
}

func (o *QueryBadRequest) Error() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryBadRequest  %+v", 400, o.Payload)
}

func (o *QueryBadRequest) String() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryBadRequest  %+v", 400, o.Payload)
}

func (o *QueryBadRequest) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryForbidden creates a QueryForbidden with default headers values
func NewQueryForbidden() *QueryForbidden {
	return &QueryForbidden{}
}

/*
QueryForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryForbidden struct {

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

// IsSuccess returns true when this query forbidden response has a 2xx status code
func (o *QueryForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query forbidden response has a 3xx status code
func (o *QueryForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query forbidden response has a 4xx status code
func (o *QueryForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query forbidden response has a 5xx status code
func (o *QueryForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query forbidden response a status code equal to that given
func (o *QueryForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query forbidden response
func (o *QueryForbidden) Code() int {
	return 403
}

func (o *QueryForbidden) Error() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryForbidden  %+v", 403, o.Payload)
}

func (o *QueryForbidden) String() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryForbidden  %+v", 403, o.Payload)
}

func (o *QueryForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryTooManyRequests creates a QueryTooManyRequests with default headers values
func NewQueryTooManyRequests() *QueryTooManyRequests {
	return &QueryTooManyRequests{}
}

/*
QueryTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryTooManyRequests struct {

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

// IsSuccess returns true when this query too many requests response has a 2xx status code
func (o *QueryTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query too many requests response has a 3xx status code
func (o *QueryTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query too many requests response has a 4xx status code
func (o *QueryTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query too many requests response has a 5xx status code
func (o *QueryTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query too many requests response a status code equal to that given
func (o *QueryTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query too many requests response
func (o *QueryTooManyRequests) Code() int {
	return 429
}

func (o *QueryTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryTooManyRequests) String() string {
	return fmt.Sprintf("[GET /reports/queries/scheduled-reports/v1][%d] queryTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
