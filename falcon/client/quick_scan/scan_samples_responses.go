// Code generated by go-swagger; DO NOT EDIT.

package quick_scan

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

// ScanSamplesReader is a Reader for the ScanSamples structure.
type ScanSamplesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ScanSamplesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewScanSamplesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewScanSamplesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewScanSamplesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewScanSamplesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewScanSamplesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /scanner/entities/scans/v1] ScanSamples", response, response.Code())
	}
}

// NewScanSamplesOK creates a ScanSamplesOK with default headers values
func NewScanSamplesOK() *ScanSamplesOK {
	return &ScanSamplesOK{}
}

/* ScanSamplesOK describes a response with status code 200, with default header values.

OK
*/
type ScanSamplesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiQueryResponse
}

// IsSuccess returns true when this scan samples o k response has a 2xx status code
func (o *ScanSamplesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this scan samples o k response has a 3xx status code
func (o *ScanSamplesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this scan samples o k response has a 4xx status code
func (o *ScanSamplesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this scan samples o k response has a 5xx status code
func (o *ScanSamplesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this scan samples o k response a status code equal to that given
func (o *ScanSamplesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the scan samples o k response
func (o *ScanSamplesOK) Code() int {
	return 200
}

func (o *ScanSamplesOK) Error() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesOK  %+v", 200, o.Payload)
}

func (o *ScanSamplesOK) String() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesOK  %+v", 200, o.Payload)
}

func (o *ScanSamplesOK) GetPayload() *models.MlscannerapiQueryResponse {
	return o.Payload
}

func (o *ScanSamplesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewScanSamplesBadRequest creates a ScanSamplesBadRequest with default headers values
func NewScanSamplesBadRequest() *ScanSamplesBadRequest {
	return &ScanSamplesBadRequest{}
}

/* ScanSamplesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ScanSamplesBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiQueryResponse
}

// IsSuccess returns true when this scan samples bad request response has a 2xx status code
func (o *ScanSamplesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this scan samples bad request response has a 3xx status code
func (o *ScanSamplesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this scan samples bad request response has a 4xx status code
func (o *ScanSamplesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this scan samples bad request response has a 5xx status code
func (o *ScanSamplesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this scan samples bad request response a status code equal to that given
func (o *ScanSamplesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the scan samples bad request response
func (o *ScanSamplesBadRequest) Code() int {
	return 400
}

func (o *ScanSamplesBadRequest) Error() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesBadRequest  %+v", 400, o.Payload)
}

func (o *ScanSamplesBadRequest) String() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesBadRequest  %+v", 400, o.Payload)
}

func (o *ScanSamplesBadRequest) GetPayload() *models.MlscannerapiQueryResponse {
	return o.Payload
}

func (o *ScanSamplesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewScanSamplesForbidden creates a ScanSamplesForbidden with default headers values
func NewScanSamplesForbidden() *ScanSamplesForbidden {
	return &ScanSamplesForbidden{}
}

/* ScanSamplesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ScanSamplesForbidden struct {

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

// IsSuccess returns true when this scan samples forbidden response has a 2xx status code
func (o *ScanSamplesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this scan samples forbidden response has a 3xx status code
func (o *ScanSamplesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this scan samples forbidden response has a 4xx status code
func (o *ScanSamplesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this scan samples forbidden response has a 5xx status code
func (o *ScanSamplesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this scan samples forbidden response a status code equal to that given
func (o *ScanSamplesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the scan samples forbidden response
func (o *ScanSamplesForbidden) Code() int {
	return 403
}

func (o *ScanSamplesForbidden) Error() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesForbidden  %+v", 403, o.Payload)
}

func (o *ScanSamplesForbidden) String() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesForbidden  %+v", 403, o.Payload)
}

func (o *ScanSamplesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ScanSamplesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewScanSamplesTooManyRequests creates a ScanSamplesTooManyRequests with default headers values
func NewScanSamplesTooManyRequests() *ScanSamplesTooManyRequests {
	return &ScanSamplesTooManyRequests{}
}

/* ScanSamplesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ScanSamplesTooManyRequests struct {

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

// IsSuccess returns true when this scan samples too many requests response has a 2xx status code
func (o *ScanSamplesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this scan samples too many requests response has a 3xx status code
func (o *ScanSamplesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this scan samples too many requests response has a 4xx status code
func (o *ScanSamplesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this scan samples too many requests response has a 5xx status code
func (o *ScanSamplesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this scan samples too many requests response a status code equal to that given
func (o *ScanSamplesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the scan samples too many requests response
func (o *ScanSamplesTooManyRequests) Code() int {
	return 429
}

func (o *ScanSamplesTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ScanSamplesTooManyRequests) String() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ScanSamplesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ScanSamplesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewScanSamplesInternalServerError creates a ScanSamplesInternalServerError with default headers values
func NewScanSamplesInternalServerError() *ScanSamplesInternalServerError {
	return &ScanSamplesInternalServerError{}
}

/* ScanSamplesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ScanSamplesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiQueryResponse
}

// IsSuccess returns true when this scan samples internal server error response has a 2xx status code
func (o *ScanSamplesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this scan samples internal server error response has a 3xx status code
func (o *ScanSamplesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this scan samples internal server error response has a 4xx status code
func (o *ScanSamplesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this scan samples internal server error response has a 5xx status code
func (o *ScanSamplesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this scan samples internal server error response a status code equal to that given
func (o *ScanSamplesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the scan samples internal server error response
func (o *ScanSamplesInternalServerError) Code() int {
	return 500
}

func (o *ScanSamplesInternalServerError) Error() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesInternalServerError  %+v", 500, o.Payload)
}

func (o *ScanSamplesInternalServerError) String() string {
	return fmt.Sprintf("[POST /scanner/entities/scans/v1][%d] scanSamplesInternalServerError  %+v", 500, o.Payload)
}

func (o *ScanSamplesInternalServerError) GetPayload() *models.MlscannerapiQueryResponse {
	return o.Payload
}

func (o *ScanSamplesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
