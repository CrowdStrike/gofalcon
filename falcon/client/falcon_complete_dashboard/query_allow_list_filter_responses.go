// Code generated by go-swagger; DO NOT EDIT.

package falcon_complete_dashboard

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

// QueryAllowListFilterReader is a Reader for the QueryAllowListFilter structure.
type QueryAllowListFilterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryAllowListFilterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryAllowListFilterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewQueryAllowListFilterForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryAllowListFilterTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /falcon-complete-dashboards/queries/allowlist/v1] QueryAllowListFilter", response, response.Code())
	}
}

// NewQueryAllowListFilterOK creates a QueryAllowListFilterOK with default headers values
func NewQueryAllowListFilterOK() *QueryAllowListFilterOK {
	return &QueryAllowListFilterOK{}
}

/*
QueryAllowListFilterOK describes a response with status code 200, with default header values.

OK
*/
type QueryAllowListFilterOK struct {

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

// IsSuccess returns true when this query allow list filter o k response has a 2xx status code
func (o *QueryAllowListFilterOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query allow list filter o k response has a 3xx status code
func (o *QueryAllowListFilterOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query allow list filter o k response has a 4xx status code
func (o *QueryAllowListFilterOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query allow list filter o k response has a 5xx status code
func (o *QueryAllowListFilterOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query allow list filter o k response a status code equal to that given
func (o *QueryAllowListFilterOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query allow list filter o k response
func (o *QueryAllowListFilterOK) Code() int {
	return 200
}

func (o *QueryAllowListFilterOK) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/allowlist/v1][%d] queryAllowListFilterOK  %+v", 200, o.Payload)
}

func (o *QueryAllowListFilterOK) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/allowlist/v1][%d] queryAllowListFilterOK  %+v", 200, o.Payload)
}

func (o *QueryAllowListFilterOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryAllowListFilterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryAllowListFilterForbidden creates a QueryAllowListFilterForbidden with default headers values
func NewQueryAllowListFilterForbidden() *QueryAllowListFilterForbidden {
	return &QueryAllowListFilterForbidden{}
}

/*
QueryAllowListFilterForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryAllowListFilterForbidden struct {

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

// IsSuccess returns true when this query allow list filter forbidden response has a 2xx status code
func (o *QueryAllowListFilterForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query allow list filter forbidden response has a 3xx status code
func (o *QueryAllowListFilterForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query allow list filter forbidden response has a 4xx status code
func (o *QueryAllowListFilterForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query allow list filter forbidden response has a 5xx status code
func (o *QueryAllowListFilterForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query allow list filter forbidden response a status code equal to that given
func (o *QueryAllowListFilterForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query allow list filter forbidden response
func (o *QueryAllowListFilterForbidden) Code() int {
	return 403
}

func (o *QueryAllowListFilterForbidden) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/allowlist/v1][%d] queryAllowListFilterForbidden  %+v", 403, o.Payload)
}

func (o *QueryAllowListFilterForbidden) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/allowlist/v1][%d] queryAllowListFilterForbidden  %+v", 403, o.Payload)
}

func (o *QueryAllowListFilterForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryAllowListFilterForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryAllowListFilterTooManyRequests creates a QueryAllowListFilterTooManyRequests with default headers values
func NewQueryAllowListFilterTooManyRequests() *QueryAllowListFilterTooManyRequests {
	return &QueryAllowListFilterTooManyRequests{}
}

/*
QueryAllowListFilterTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryAllowListFilterTooManyRequests struct {

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

// IsSuccess returns true when this query allow list filter too many requests response has a 2xx status code
func (o *QueryAllowListFilterTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query allow list filter too many requests response has a 3xx status code
func (o *QueryAllowListFilterTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query allow list filter too many requests response has a 4xx status code
func (o *QueryAllowListFilterTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query allow list filter too many requests response has a 5xx status code
func (o *QueryAllowListFilterTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query allow list filter too many requests response a status code equal to that given
func (o *QueryAllowListFilterTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query allow list filter too many requests response
func (o *QueryAllowListFilterTooManyRequests) Code() int {
	return 429
}

func (o *QueryAllowListFilterTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/allowlist/v1][%d] queryAllowListFilterTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryAllowListFilterTooManyRequests) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/allowlist/v1][%d] queryAllowListFilterTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryAllowListFilterTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryAllowListFilterTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
