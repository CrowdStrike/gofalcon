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

// QueryAlertIdsByFilterReader is a Reader for the QueryAlertIdsByFilter structure.
type QueryAlertIdsByFilterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryAlertIdsByFilterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryAlertIdsByFilterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewQueryAlertIdsByFilterForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryAlertIdsByFilterTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /falcon-complete-dashboards/queries/alerts/v1] QueryAlertIdsByFilter", response, response.Code())
	}
}

// NewQueryAlertIdsByFilterOK creates a QueryAlertIdsByFilterOK with default headers values
func NewQueryAlertIdsByFilterOK() *QueryAlertIdsByFilterOK {
	return &QueryAlertIdsByFilterOK{}
}

/*
QueryAlertIdsByFilterOK describes a response with status code 200, with default header values.

OK
*/
type QueryAlertIdsByFilterOK struct {

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

// IsSuccess returns true when this query alert ids by filter o k response has a 2xx status code
func (o *QueryAlertIdsByFilterOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query alert ids by filter o k response has a 3xx status code
func (o *QueryAlertIdsByFilterOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query alert ids by filter o k response has a 4xx status code
func (o *QueryAlertIdsByFilterOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query alert ids by filter o k response has a 5xx status code
func (o *QueryAlertIdsByFilterOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query alert ids by filter o k response a status code equal to that given
func (o *QueryAlertIdsByFilterOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query alert ids by filter o k response
func (o *QueryAlertIdsByFilterOK) Code() int {
	return 200
}

func (o *QueryAlertIdsByFilterOK) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/alerts/v1][%d] queryAlertIdsByFilterOK  %+v", 200, o.Payload)
}

func (o *QueryAlertIdsByFilterOK) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/alerts/v1][%d] queryAlertIdsByFilterOK  %+v", 200, o.Payload)
}

func (o *QueryAlertIdsByFilterOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryAlertIdsByFilterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryAlertIdsByFilterForbidden creates a QueryAlertIdsByFilterForbidden with default headers values
func NewQueryAlertIdsByFilterForbidden() *QueryAlertIdsByFilterForbidden {
	return &QueryAlertIdsByFilterForbidden{}
}

/*
QueryAlertIdsByFilterForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryAlertIdsByFilterForbidden struct {

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

// IsSuccess returns true when this query alert ids by filter forbidden response has a 2xx status code
func (o *QueryAlertIdsByFilterForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query alert ids by filter forbidden response has a 3xx status code
func (o *QueryAlertIdsByFilterForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query alert ids by filter forbidden response has a 4xx status code
func (o *QueryAlertIdsByFilterForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query alert ids by filter forbidden response has a 5xx status code
func (o *QueryAlertIdsByFilterForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query alert ids by filter forbidden response a status code equal to that given
func (o *QueryAlertIdsByFilterForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query alert ids by filter forbidden response
func (o *QueryAlertIdsByFilterForbidden) Code() int {
	return 403
}

func (o *QueryAlertIdsByFilterForbidden) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/alerts/v1][%d] queryAlertIdsByFilterForbidden  %+v", 403, o.Payload)
}

func (o *QueryAlertIdsByFilterForbidden) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/alerts/v1][%d] queryAlertIdsByFilterForbidden  %+v", 403, o.Payload)
}

func (o *QueryAlertIdsByFilterForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryAlertIdsByFilterForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryAlertIdsByFilterTooManyRequests creates a QueryAlertIdsByFilterTooManyRequests with default headers values
func NewQueryAlertIdsByFilterTooManyRequests() *QueryAlertIdsByFilterTooManyRequests {
	return &QueryAlertIdsByFilterTooManyRequests{}
}

/*
QueryAlertIdsByFilterTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryAlertIdsByFilterTooManyRequests struct {

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

// IsSuccess returns true when this query alert ids by filter too many requests response has a 2xx status code
func (o *QueryAlertIdsByFilterTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query alert ids by filter too many requests response has a 3xx status code
func (o *QueryAlertIdsByFilterTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query alert ids by filter too many requests response has a 4xx status code
func (o *QueryAlertIdsByFilterTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query alert ids by filter too many requests response has a 5xx status code
func (o *QueryAlertIdsByFilterTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query alert ids by filter too many requests response a status code equal to that given
func (o *QueryAlertIdsByFilterTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query alert ids by filter too many requests response
func (o *QueryAlertIdsByFilterTooManyRequests) Code() int {
	return 429
}

func (o *QueryAlertIdsByFilterTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/alerts/v1][%d] queryAlertIdsByFilterTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryAlertIdsByFilterTooManyRequests) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/alerts/v1][%d] queryAlertIdsByFilterTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryAlertIdsByFilterTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryAlertIdsByFilterTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
