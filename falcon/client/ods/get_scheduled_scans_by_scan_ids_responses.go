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

	"github.com/aslape/gofalcon/falcon/models"
)

// GetScheduledScansByScanIdsReader is a Reader for the GetScheduledScansByScanIds structure.
type GetScheduledScansByScanIdsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetScheduledScansByScanIdsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetScheduledScansByScanIdsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetScheduledScansByScanIdsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetScheduledScansByScanIdsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetScheduledScansByScanIdsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /ods/entities/scheduled-scans/v1] get-scheduled-scans-by-scan-ids", response, response.Code())
	}
}

// NewGetScheduledScansByScanIdsOK creates a GetScheduledScansByScanIdsOK with default headers values
func NewGetScheduledScansByScanIdsOK() *GetScheduledScansByScanIdsOK {
	return &GetScheduledScansByScanIdsOK{}
}

/*
GetScheduledScansByScanIdsOK describes a response with status code 200, with default header values.

OK
*/
type GetScheduledScansByScanIdsOK struct {

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

// IsSuccess returns true when this get scheduled scans by scan ids o k response has a 2xx status code
func (o *GetScheduledScansByScanIdsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get scheduled scans by scan ids o k response has a 3xx status code
func (o *GetScheduledScansByScanIdsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scheduled scans by scan ids o k response has a 4xx status code
func (o *GetScheduledScansByScanIdsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get scheduled scans by scan ids o k response has a 5xx status code
func (o *GetScheduledScansByScanIdsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get scheduled scans by scan ids o k response a status code equal to that given
func (o *GetScheduledScansByScanIdsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get scheduled scans by scan ids o k response
func (o *GetScheduledScansByScanIdsOK) Code() int {
	return 200
}

func (o *GetScheduledScansByScanIdsOK) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsOK  %+v", 200, o.Payload)
}

func (o *GetScheduledScansByScanIdsOK) String() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsOK  %+v", 200, o.Payload)
}

func (o *GetScheduledScansByScanIdsOK) GetPayload() *models.EntitiesODSScheduleScanResponse {
	return o.Payload
}

func (o *GetScheduledScansByScanIdsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScheduledScansByScanIdsForbidden creates a GetScheduledScansByScanIdsForbidden with default headers values
func NewGetScheduledScansByScanIdsForbidden() *GetScheduledScansByScanIdsForbidden {
	return &GetScheduledScansByScanIdsForbidden{}
}

/*
GetScheduledScansByScanIdsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetScheduledScansByScanIdsForbidden struct {

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

// IsSuccess returns true when this get scheduled scans by scan ids forbidden response has a 2xx status code
func (o *GetScheduledScansByScanIdsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scheduled scans by scan ids forbidden response has a 3xx status code
func (o *GetScheduledScansByScanIdsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scheduled scans by scan ids forbidden response has a 4xx status code
func (o *GetScheduledScansByScanIdsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scheduled scans by scan ids forbidden response has a 5xx status code
func (o *GetScheduledScansByScanIdsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get scheduled scans by scan ids forbidden response a status code equal to that given
func (o *GetScheduledScansByScanIdsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get scheduled scans by scan ids forbidden response
func (o *GetScheduledScansByScanIdsForbidden) Code() int {
	return 403
}

func (o *GetScheduledScansByScanIdsForbidden) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsForbidden  %+v", 403, o.Payload)
}

func (o *GetScheduledScansByScanIdsForbidden) String() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsForbidden  %+v", 403, o.Payload)
}

func (o *GetScheduledScansByScanIdsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScheduledScansByScanIdsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScheduledScansByScanIdsNotFound creates a GetScheduledScansByScanIdsNotFound with default headers values
func NewGetScheduledScansByScanIdsNotFound() *GetScheduledScansByScanIdsNotFound {
	return &GetScheduledScansByScanIdsNotFound{}
}

/*
GetScheduledScansByScanIdsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetScheduledScansByScanIdsNotFound struct {

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

// IsSuccess returns true when this get scheduled scans by scan ids not found response has a 2xx status code
func (o *GetScheduledScansByScanIdsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scheduled scans by scan ids not found response has a 3xx status code
func (o *GetScheduledScansByScanIdsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scheduled scans by scan ids not found response has a 4xx status code
func (o *GetScheduledScansByScanIdsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scheduled scans by scan ids not found response has a 5xx status code
func (o *GetScheduledScansByScanIdsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get scheduled scans by scan ids not found response a status code equal to that given
func (o *GetScheduledScansByScanIdsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get scheduled scans by scan ids not found response
func (o *GetScheduledScansByScanIdsNotFound) Code() int {
	return 404
}

func (o *GetScheduledScansByScanIdsNotFound) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsNotFound  %+v", 404, o.Payload)
}

func (o *GetScheduledScansByScanIdsNotFound) String() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsNotFound  %+v", 404, o.Payload)
}

func (o *GetScheduledScansByScanIdsNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetScheduledScansByScanIdsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScheduledScansByScanIdsTooManyRequests creates a GetScheduledScansByScanIdsTooManyRequests with default headers values
func NewGetScheduledScansByScanIdsTooManyRequests() *GetScheduledScansByScanIdsTooManyRequests {
	return &GetScheduledScansByScanIdsTooManyRequests{}
}

/*
GetScheduledScansByScanIdsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetScheduledScansByScanIdsTooManyRequests struct {

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

// IsSuccess returns true when this get scheduled scans by scan ids too many requests response has a 2xx status code
func (o *GetScheduledScansByScanIdsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scheduled scans by scan ids too many requests response has a 3xx status code
func (o *GetScheduledScansByScanIdsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scheduled scans by scan ids too many requests response has a 4xx status code
func (o *GetScheduledScansByScanIdsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scheduled scans by scan ids too many requests response has a 5xx status code
func (o *GetScheduledScansByScanIdsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get scheduled scans by scan ids too many requests response a status code equal to that given
func (o *GetScheduledScansByScanIdsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get scheduled scans by scan ids too many requests response
func (o *GetScheduledScansByScanIdsTooManyRequests) Code() int {
	return 429
}

func (o *GetScheduledScansByScanIdsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScheduledScansByScanIdsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /ods/entities/scheduled-scans/v1][%d] getScheduledScansByScanIdsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScheduledScansByScanIdsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScheduledScansByScanIdsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
