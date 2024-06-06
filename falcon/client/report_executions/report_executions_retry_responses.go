// Code generated by go-swagger; DO NOT EDIT.

package report_executions

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

// ReportExecutionsRetryReader is a Reader for the ReportExecutionsRetry structure.
type ReportExecutionsRetryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReportExecutionsRetryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReportExecutionsRetryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewReportExecutionsRetryBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewReportExecutionsRetryForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewReportExecutionsRetryTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /reports/entities/report-executions-retry/v1] report-executions.retry", response, response.Code())
	}
}

// NewReportExecutionsRetryOK creates a ReportExecutionsRetryOK with default headers values
func NewReportExecutionsRetryOK() *ReportExecutionsRetryOK {
	return &ReportExecutionsRetryOK{}
}

/*
ReportExecutionsRetryOK describes a response with status code 200, with default header values.

OK
*/
type ReportExecutionsRetryOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainReportExecutionsResponseV1
}

// IsSuccess returns true when this report executions retry o k response has a 2xx status code
func (o *ReportExecutionsRetryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this report executions retry o k response has a 3xx status code
func (o *ReportExecutionsRetryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this report executions retry o k response has a 4xx status code
func (o *ReportExecutionsRetryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this report executions retry o k response has a 5xx status code
func (o *ReportExecutionsRetryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this report executions retry o k response a status code equal to that given
func (o *ReportExecutionsRetryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the report executions retry o k response
func (o *ReportExecutionsRetryOK) Code() int {
	return 200
}

func (o *ReportExecutionsRetryOK) Error() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryOK  %+v", 200, o.Payload)
}

func (o *ReportExecutionsRetryOK) String() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryOK  %+v", 200, o.Payload)
}

func (o *ReportExecutionsRetryOK) GetPayload() *models.DomainReportExecutionsResponseV1 {
	return o.Payload
}

func (o *ReportExecutionsRetryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainReportExecutionsResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReportExecutionsRetryBadRequest creates a ReportExecutionsRetryBadRequest with default headers values
func NewReportExecutionsRetryBadRequest() *ReportExecutionsRetryBadRequest {
	return &ReportExecutionsRetryBadRequest{}
}

/*
ReportExecutionsRetryBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ReportExecutionsRetryBadRequest struct {

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

// IsSuccess returns true when this report executions retry bad request response has a 2xx status code
func (o *ReportExecutionsRetryBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this report executions retry bad request response has a 3xx status code
func (o *ReportExecutionsRetryBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this report executions retry bad request response has a 4xx status code
func (o *ReportExecutionsRetryBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this report executions retry bad request response has a 5xx status code
func (o *ReportExecutionsRetryBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this report executions retry bad request response a status code equal to that given
func (o *ReportExecutionsRetryBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the report executions retry bad request response
func (o *ReportExecutionsRetryBadRequest) Code() int {
	return 400
}

func (o *ReportExecutionsRetryBadRequest) Error() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryBadRequest  %+v", 400, o.Payload)
}

func (o *ReportExecutionsRetryBadRequest) String() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryBadRequest  %+v", 400, o.Payload)
}

func (o *ReportExecutionsRetryBadRequest) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReportExecutionsRetryBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReportExecutionsRetryForbidden creates a ReportExecutionsRetryForbidden with default headers values
func NewReportExecutionsRetryForbidden() *ReportExecutionsRetryForbidden {
	return &ReportExecutionsRetryForbidden{}
}

/*
ReportExecutionsRetryForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ReportExecutionsRetryForbidden struct {

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

// IsSuccess returns true when this report executions retry forbidden response has a 2xx status code
func (o *ReportExecutionsRetryForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this report executions retry forbidden response has a 3xx status code
func (o *ReportExecutionsRetryForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this report executions retry forbidden response has a 4xx status code
func (o *ReportExecutionsRetryForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this report executions retry forbidden response has a 5xx status code
func (o *ReportExecutionsRetryForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this report executions retry forbidden response a status code equal to that given
func (o *ReportExecutionsRetryForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the report executions retry forbidden response
func (o *ReportExecutionsRetryForbidden) Code() int {
	return 403
}

func (o *ReportExecutionsRetryForbidden) Error() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryForbidden  %+v", 403, o.Payload)
}

func (o *ReportExecutionsRetryForbidden) String() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryForbidden  %+v", 403, o.Payload)
}

func (o *ReportExecutionsRetryForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReportExecutionsRetryForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReportExecutionsRetryTooManyRequests creates a ReportExecutionsRetryTooManyRequests with default headers values
func NewReportExecutionsRetryTooManyRequests() *ReportExecutionsRetryTooManyRequests {
	return &ReportExecutionsRetryTooManyRequests{}
}

/*
ReportExecutionsRetryTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ReportExecutionsRetryTooManyRequests struct {

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

// IsSuccess returns true when this report executions retry too many requests response has a 2xx status code
func (o *ReportExecutionsRetryTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this report executions retry too many requests response has a 3xx status code
func (o *ReportExecutionsRetryTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this report executions retry too many requests response has a 4xx status code
func (o *ReportExecutionsRetryTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this report executions retry too many requests response has a 5xx status code
func (o *ReportExecutionsRetryTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this report executions retry too many requests response a status code equal to that given
func (o *ReportExecutionsRetryTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the report executions retry too many requests response
func (o *ReportExecutionsRetryTooManyRequests) Code() int {
	return 429
}

func (o *ReportExecutionsRetryTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReportExecutionsRetryTooManyRequests) String() string {
	return fmt.Sprintf("[POST /reports/entities/report-executions-retry/v1][%d] reportExecutionsRetryTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReportExecutionsRetryTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReportExecutionsRetryTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
