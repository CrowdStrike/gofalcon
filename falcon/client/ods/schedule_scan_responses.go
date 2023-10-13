// Code generated by go-swagger; DO NOT EDIT.

package ods

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

// ScheduleScanReader is a Reader for the ScheduleScan structure.
type ScheduleScanReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ScheduleScanReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewScheduleScanCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewScheduleScanForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewScheduleScanTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /ods/entities/scheduled-scans/v1] schedule-scan", response, response.Code())
	}
}

// NewScheduleScanCreated creates a ScheduleScanCreated with default headers values
func NewScheduleScanCreated() *ScheduleScanCreated {
	return &ScheduleScanCreated{}
}

/* ScheduleScanCreated describes a response with status code 201, with default header values.

OK
*/
type ScheduleScanCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.EntitiesODSScheduleScanResponse
}

// IsSuccess returns true when this schedule scan created response has a 2xx status code
func (o *ScheduleScanCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this schedule scan created response has a 3xx status code
func (o *ScheduleScanCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this schedule scan created response has a 4xx status code
func (o *ScheduleScanCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this schedule scan created response has a 5xx status code
func (o *ScheduleScanCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this schedule scan created response a status code equal to that given
func (o *ScheduleScanCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the schedule scan created response
func (o *ScheduleScanCreated) Code() int {
	return 201
}

func (o *ScheduleScanCreated) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scheduled-scans/v1][%d] scheduleScanCreated  %+v", 201, o.Payload)
}

func (o *ScheduleScanCreated) String() string {
	return fmt.Sprintf("[POST /ods/entities/scheduled-scans/v1][%d] scheduleScanCreated  %+v", 201, o.Payload)
}

func (o *ScheduleScanCreated) GetPayload() *models.EntitiesODSScheduleScanResponse {
	return o.Payload
}

func (o *ScheduleScanCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.EntitiesODSScheduleScanResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewScheduleScanForbidden creates a ScheduleScanForbidden with default headers values
func NewScheduleScanForbidden() *ScheduleScanForbidden {
	return &ScheduleScanForbidden{}
}

/* ScheduleScanForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ScheduleScanForbidden struct {

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

// IsSuccess returns true when this schedule scan forbidden response has a 2xx status code
func (o *ScheduleScanForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this schedule scan forbidden response has a 3xx status code
func (o *ScheduleScanForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this schedule scan forbidden response has a 4xx status code
func (o *ScheduleScanForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this schedule scan forbidden response has a 5xx status code
func (o *ScheduleScanForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this schedule scan forbidden response a status code equal to that given
func (o *ScheduleScanForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the schedule scan forbidden response
func (o *ScheduleScanForbidden) Code() int {
	return 403
}

func (o *ScheduleScanForbidden) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scheduled-scans/v1][%d] scheduleScanForbidden  %+v", 403, o.Payload)
}

func (o *ScheduleScanForbidden) String() string {
	return fmt.Sprintf("[POST /ods/entities/scheduled-scans/v1][%d] scheduleScanForbidden  %+v", 403, o.Payload)
}

func (o *ScheduleScanForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ScheduleScanForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewScheduleScanTooManyRequests creates a ScheduleScanTooManyRequests with default headers values
func NewScheduleScanTooManyRequests() *ScheduleScanTooManyRequests {
	return &ScheduleScanTooManyRequests{}
}

/* ScheduleScanTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ScheduleScanTooManyRequests struct {

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

// IsSuccess returns true when this schedule scan too many requests response has a 2xx status code
func (o *ScheduleScanTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this schedule scan too many requests response has a 3xx status code
func (o *ScheduleScanTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this schedule scan too many requests response has a 4xx status code
func (o *ScheduleScanTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this schedule scan too many requests response has a 5xx status code
func (o *ScheduleScanTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this schedule scan too many requests response a status code equal to that given
func (o *ScheduleScanTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the schedule scan too many requests response
func (o *ScheduleScanTooManyRequests) Code() int {
	return 429
}

func (o *ScheduleScanTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scheduled-scans/v1][%d] scheduleScanTooManyRequests  %+v", 429, o.Payload)
}

func (o *ScheduleScanTooManyRequests) String() string {
	return fmt.Sprintf("[POST /ods/entities/scheduled-scans/v1][%d] scheduleScanTooManyRequests  %+v", 429, o.Payload)
}

func (o *ScheduleScanTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ScheduleScanTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
