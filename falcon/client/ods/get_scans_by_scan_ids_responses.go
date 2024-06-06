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

// GetScansByScanIdsReader is a Reader for the GetScansByScanIds structure.
type GetScansByScanIdsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetScansByScanIdsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetScansByScanIdsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetScansByScanIdsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetScansByScanIdsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetScansByScanIdsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /ods/entities/scans/v1] get-scans-by-scan-ids", response, response.Code())
	}
}

// NewGetScansByScanIdsOK creates a GetScansByScanIdsOK with default headers values
func NewGetScansByScanIdsOK() *GetScansByScanIdsOK {
	return &GetScansByScanIdsOK{}
}

/*
GetScansByScanIdsOK describes a response with status code 200, with default header values.

OK
*/
type GetScansByScanIdsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.EntitiesODSScanResponse
}

// IsSuccess returns true when this get scans by scan ids o k response has a 2xx status code
func (o *GetScansByScanIdsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get scans by scan ids o k response has a 3xx status code
func (o *GetScansByScanIdsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans by scan ids o k response has a 4xx status code
func (o *GetScansByScanIdsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get scans by scan ids o k response has a 5xx status code
func (o *GetScansByScanIdsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans by scan ids o k response a status code equal to that given
func (o *GetScansByScanIdsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get scans by scan ids o k response
func (o *GetScansByScanIdsOK) Code() int {
	return 200
}

func (o *GetScansByScanIdsOK) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsOK  %+v", 200, o.Payload)
}

func (o *GetScansByScanIdsOK) String() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsOK  %+v", 200, o.Payload)
}

func (o *GetScansByScanIdsOK) GetPayload() *models.EntitiesODSScanResponse {
	return o.Payload
}

func (o *GetScansByScanIdsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.EntitiesODSScanResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScansByScanIdsForbidden creates a GetScansByScanIdsForbidden with default headers values
func NewGetScansByScanIdsForbidden() *GetScansByScanIdsForbidden {
	return &GetScansByScanIdsForbidden{}
}

/*
GetScansByScanIdsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetScansByScanIdsForbidden struct {

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

// IsSuccess returns true when this get scans by scan ids forbidden response has a 2xx status code
func (o *GetScansByScanIdsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans by scan ids forbidden response has a 3xx status code
func (o *GetScansByScanIdsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans by scan ids forbidden response has a 4xx status code
func (o *GetScansByScanIdsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans by scan ids forbidden response has a 5xx status code
func (o *GetScansByScanIdsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans by scan ids forbidden response a status code equal to that given
func (o *GetScansByScanIdsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get scans by scan ids forbidden response
func (o *GetScansByScanIdsForbidden) Code() int {
	return 403
}

func (o *GetScansByScanIdsForbidden) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsForbidden  %+v", 403, o.Payload)
}

func (o *GetScansByScanIdsForbidden) String() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsForbidden  %+v", 403, o.Payload)
}

func (o *GetScansByScanIdsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScansByScanIdsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScansByScanIdsNotFound creates a GetScansByScanIdsNotFound with default headers values
func NewGetScansByScanIdsNotFound() *GetScansByScanIdsNotFound {
	return &GetScansByScanIdsNotFound{}
}

/*
GetScansByScanIdsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetScansByScanIdsNotFound struct {

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

// IsSuccess returns true when this get scans by scan ids not found response has a 2xx status code
func (o *GetScansByScanIdsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans by scan ids not found response has a 3xx status code
func (o *GetScansByScanIdsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans by scan ids not found response has a 4xx status code
func (o *GetScansByScanIdsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans by scan ids not found response has a 5xx status code
func (o *GetScansByScanIdsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans by scan ids not found response a status code equal to that given
func (o *GetScansByScanIdsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get scans by scan ids not found response
func (o *GetScansByScanIdsNotFound) Code() int {
	return 404
}

func (o *GetScansByScanIdsNotFound) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsNotFound  %+v", 404, o.Payload)
}

func (o *GetScansByScanIdsNotFound) String() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsNotFound  %+v", 404, o.Payload)
}

func (o *GetScansByScanIdsNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetScansByScanIdsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScansByScanIdsTooManyRequests creates a GetScansByScanIdsTooManyRequests with default headers values
func NewGetScansByScanIdsTooManyRequests() *GetScansByScanIdsTooManyRequests {
	return &GetScansByScanIdsTooManyRequests{}
}

/*
GetScansByScanIdsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetScansByScanIdsTooManyRequests struct {

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

// IsSuccess returns true when this get scans by scan ids too many requests response has a 2xx status code
func (o *GetScansByScanIdsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans by scan ids too many requests response has a 3xx status code
func (o *GetScansByScanIdsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans by scan ids too many requests response has a 4xx status code
func (o *GetScansByScanIdsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans by scan ids too many requests response has a 5xx status code
func (o *GetScansByScanIdsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans by scan ids too many requests response a status code equal to that given
func (o *GetScansByScanIdsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get scans by scan ids too many requests response
func (o *GetScansByScanIdsTooManyRequests) Code() int {
	return 429
}

func (o *GetScansByScanIdsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScansByScanIdsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /ods/entities/scans/v1][%d] getScansByScanIdsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScansByScanIdsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScansByScanIdsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
