// Code generated by go-swagger; DO NOT EDIT.

package real_time_response

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

// RTRListFilesReader is a Reader for the RTRListFiles structure.
type RTRListFilesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RTRListFilesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRTRListFilesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRTRListFilesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRTRListFilesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRTRListFilesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRTRListFilesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /real-time-response/entities/file/v1] RTR-ListFiles", response, response.Code())
	}
}

// NewRTRListFilesOK creates a RTRListFilesOK with default headers values
func NewRTRListFilesOK() *RTRListFilesOK {
	return &RTRListFilesOK{}
}

/*
RTRListFilesOK describes a response with status code 200, with default header values.

OK
*/
type RTRListFilesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainListFilesResponseWrapper
}

// IsSuccess returns true when this r t r list files o k response has a 2xx status code
func (o *RTRListFilesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this r t r list files o k response has a 3xx status code
func (o *RTRListFilesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list files o k response has a 4xx status code
func (o *RTRListFilesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this r t r list files o k response has a 5xx status code
func (o *RTRListFilesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list files o k response a status code equal to that given
func (o *RTRListFilesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the r t r list files o k response
func (o *RTRListFilesOK) Code() int {
	return 200
}

func (o *RTRListFilesOK) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesOK  %+v", 200, o.Payload)
}

func (o *RTRListFilesOK) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesOK  %+v", 200, o.Payload)
}

func (o *RTRListFilesOK) GetPayload() *models.DomainListFilesResponseWrapper {
	return o.Payload
}

func (o *RTRListFilesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainListFilesResponseWrapper)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRTRListFilesBadRequest creates a RTRListFilesBadRequest with default headers values
func NewRTRListFilesBadRequest() *RTRListFilesBadRequest {
	return &RTRListFilesBadRequest{}
}

/*
RTRListFilesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RTRListFilesBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIError
}

// IsSuccess returns true when this r t r list files bad request response has a 2xx status code
func (o *RTRListFilesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list files bad request response has a 3xx status code
func (o *RTRListFilesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list files bad request response has a 4xx status code
func (o *RTRListFilesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list files bad request response has a 5xx status code
func (o *RTRListFilesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list files bad request response a status code equal to that given
func (o *RTRListFilesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the r t r list files bad request response
func (o *RTRListFilesBadRequest) Code() int {
	return 400
}

func (o *RTRListFilesBadRequest) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesBadRequest  %+v", 400, o.Payload)
}

func (o *RTRListFilesBadRequest) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesBadRequest  %+v", 400, o.Payload)
}

func (o *RTRListFilesBadRequest) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRListFilesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRTRListFilesForbidden creates a RTRListFilesForbidden with default headers values
func NewRTRListFilesForbidden() *RTRListFilesForbidden {
	return &RTRListFilesForbidden{}
}

/*
RTRListFilesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RTRListFilesForbidden struct {

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

// IsSuccess returns true when this r t r list files forbidden response has a 2xx status code
func (o *RTRListFilesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list files forbidden response has a 3xx status code
func (o *RTRListFilesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list files forbidden response has a 4xx status code
func (o *RTRListFilesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list files forbidden response has a 5xx status code
func (o *RTRListFilesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list files forbidden response a status code equal to that given
func (o *RTRListFilesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the r t r list files forbidden response
func (o *RTRListFilesForbidden) Code() int {
	return 403
}

func (o *RTRListFilesForbidden) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesForbidden  %+v", 403, o.Payload)
}

func (o *RTRListFilesForbidden) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesForbidden  %+v", 403, o.Payload)
}

func (o *RTRListFilesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRListFilesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRTRListFilesNotFound creates a RTRListFilesNotFound with default headers values
func NewRTRListFilesNotFound() *RTRListFilesNotFound {
	return &RTRListFilesNotFound{}
}

/*
RTRListFilesNotFound describes a response with status code 404, with default header values.

Not Found
*/
type RTRListFilesNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainAPIError
}

// IsSuccess returns true when this r t r list files not found response has a 2xx status code
func (o *RTRListFilesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list files not found response has a 3xx status code
func (o *RTRListFilesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list files not found response has a 4xx status code
func (o *RTRListFilesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list files not found response has a 5xx status code
func (o *RTRListFilesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list files not found response a status code equal to that given
func (o *RTRListFilesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the r t r list files not found response
func (o *RTRListFilesNotFound) Code() int {
	return 404
}

func (o *RTRListFilesNotFound) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesNotFound  %+v", 404, o.Payload)
}

func (o *RTRListFilesNotFound) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesNotFound  %+v", 404, o.Payload)
}

func (o *RTRListFilesNotFound) GetPayload() *models.DomainAPIError {
	return o.Payload
}

func (o *RTRListFilesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRTRListFilesTooManyRequests creates a RTRListFilesTooManyRequests with default headers values
func NewRTRListFilesTooManyRequests() *RTRListFilesTooManyRequests {
	return &RTRListFilesTooManyRequests{}
}

/*
RTRListFilesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RTRListFilesTooManyRequests struct {

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

// IsSuccess returns true when this r t r list files too many requests response has a 2xx status code
func (o *RTRListFilesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this r t r list files too many requests response has a 3xx status code
func (o *RTRListFilesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this r t r list files too many requests response has a 4xx status code
func (o *RTRListFilesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this r t r list files too many requests response has a 5xx status code
func (o *RTRListFilesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this r t r list files too many requests response a status code equal to that given
func (o *RTRListFilesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the r t r list files too many requests response
func (o *RTRListFilesTooManyRequests) Code() int {
	return 429
}

func (o *RTRListFilesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRListFilesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /real-time-response/entities/file/v1][%d] rTRListFilesTooManyRequests  %+v", 429, o.Payload)
}

func (o *RTRListFilesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RTRListFilesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
