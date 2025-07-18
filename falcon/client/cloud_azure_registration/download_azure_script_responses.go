// Code generated by go-swagger; DO NOT EDIT.

package cloud_azure_registration

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

// DownloadAzureScriptReader is a Reader for the DownloadAzureScript structure.
type DownloadAzureScriptReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DownloadAzureScriptReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDownloadAzureScriptOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDownloadAzureScriptBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDownloadAzureScriptForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDownloadAzureScriptNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDownloadAzureScriptTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDownloadAzureScriptInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /cloud-security-registration-azure/entities/scripts/v1] download_azure_script", response, response.Code())
	}
}

// NewDownloadAzureScriptOK creates a DownloadAzureScriptOK with default headers values
func NewDownloadAzureScriptOK() *DownloadAzureScriptOK {
	return &DownloadAzureScriptOK{}
}

/*
DownloadAzureScriptOK describes a response with status code 200, with default header values.

OK
*/
type DownloadAzureScriptOK struct {

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

// IsSuccess returns true when this download azure script o k response has a 2xx status code
func (o *DownloadAzureScriptOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this download azure script o k response has a 3xx status code
func (o *DownloadAzureScriptOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this download azure script o k response has a 4xx status code
func (o *DownloadAzureScriptOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this download azure script o k response has a 5xx status code
func (o *DownloadAzureScriptOK) IsServerError() bool {
	return false
}

// IsCode returns true when this download azure script o k response a status code equal to that given
func (o *DownloadAzureScriptOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the download azure script o k response
func (o *DownloadAzureScriptOK) Code() int {
	return 200
}

func (o *DownloadAzureScriptOK) Error() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptOK ", 200)
}

func (o *DownloadAzureScriptOK) String() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptOK ", 200)
}

func (o *DownloadAzureScriptOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDownloadAzureScriptBadRequest creates a DownloadAzureScriptBadRequest with default headers values
func NewDownloadAzureScriptBadRequest() *DownloadAzureScriptBadRequest {
	return &DownloadAzureScriptBadRequest{}
}

/*
DownloadAzureScriptBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DownloadAzureScriptBadRequest struct {

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

// IsSuccess returns true when this download azure script bad request response has a 2xx status code
func (o *DownloadAzureScriptBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this download azure script bad request response has a 3xx status code
func (o *DownloadAzureScriptBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this download azure script bad request response has a 4xx status code
func (o *DownloadAzureScriptBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this download azure script bad request response has a 5xx status code
func (o *DownloadAzureScriptBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this download azure script bad request response a status code equal to that given
func (o *DownloadAzureScriptBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the download azure script bad request response
func (o *DownloadAzureScriptBadRequest) Code() int {
	return 400
}

func (o *DownloadAzureScriptBadRequest) Error() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptBadRequest  %+v", 400, o.Payload)
}

func (o *DownloadAzureScriptBadRequest) String() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptBadRequest  %+v", 400, o.Payload)
}

func (o *DownloadAzureScriptBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DownloadAzureScriptBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDownloadAzureScriptForbidden creates a DownloadAzureScriptForbidden with default headers values
func NewDownloadAzureScriptForbidden() *DownloadAzureScriptForbidden {
	return &DownloadAzureScriptForbidden{}
}

/*
DownloadAzureScriptForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DownloadAzureScriptForbidden struct {

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

// IsSuccess returns true when this download azure script forbidden response has a 2xx status code
func (o *DownloadAzureScriptForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this download azure script forbidden response has a 3xx status code
func (o *DownloadAzureScriptForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this download azure script forbidden response has a 4xx status code
func (o *DownloadAzureScriptForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this download azure script forbidden response has a 5xx status code
func (o *DownloadAzureScriptForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this download azure script forbidden response a status code equal to that given
func (o *DownloadAzureScriptForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the download azure script forbidden response
func (o *DownloadAzureScriptForbidden) Code() int {
	return 403
}

func (o *DownloadAzureScriptForbidden) Error() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptForbidden  %+v", 403, o.Payload)
}

func (o *DownloadAzureScriptForbidden) String() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptForbidden  %+v", 403, o.Payload)
}

func (o *DownloadAzureScriptForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DownloadAzureScriptForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDownloadAzureScriptNotFound creates a DownloadAzureScriptNotFound with default headers values
func NewDownloadAzureScriptNotFound() *DownloadAzureScriptNotFound {
	return &DownloadAzureScriptNotFound{}
}

/*
DownloadAzureScriptNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DownloadAzureScriptNotFound struct {

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

// IsSuccess returns true when this download azure script not found response has a 2xx status code
func (o *DownloadAzureScriptNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this download azure script not found response has a 3xx status code
func (o *DownloadAzureScriptNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this download azure script not found response has a 4xx status code
func (o *DownloadAzureScriptNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this download azure script not found response has a 5xx status code
func (o *DownloadAzureScriptNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this download azure script not found response a status code equal to that given
func (o *DownloadAzureScriptNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the download azure script not found response
func (o *DownloadAzureScriptNotFound) Code() int {
	return 404
}

func (o *DownloadAzureScriptNotFound) Error() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptNotFound  %+v", 404, o.Payload)
}

func (o *DownloadAzureScriptNotFound) String() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptNotFound  %+v", 404, o.Payload)
}

func (o *DownloadAzureScriptNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DownloadAzureScriptNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDownloadAzureScriptTooManyRequests creates a DownloadAzureScriptTooManyRequests with default headers values
func NewDownloadAzureScriptTooManyRequests() *DownloadAzureScriptTooManyRequests {
	return &DownloadAzureScriptTooManyRequests{}
}

/*
DownloadAzureScriptTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DownloadAzureScriptTooManyRequests struct {

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

// IsSuccess returns true when this download azure script too many requests response has a 2xx status code
func (o *DownloadAzureScriptTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this download azure script too many requests response has a 3xx status code
func (o *DownloadAzureScriptTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this download azure script too many requests response has a 4xx status code
func (o *DownloadAzureScriptTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this download azure script too many requests response has a 5xx status code
func (o *DownloadAzureScriptTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this download azure script too many requests response a status code equal to that given
func (o *DownloadAzureScriptTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the download azure script too many requests response
func (o *DownloadAzureScriptTooManyRequests) Code() int {
	return 429
}

func (o *DownloadAzureScriptTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *DownloadAzureScriptTooManyRequests) String() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *DownloadAzureScriptTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DownloadAzureScriptTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDownloadAzureScriptInternalServerError creates a DownloadAzureScriptInternalServerError with default headers values
func NewDownloadAzureScriptInternalServerError() *DownloadAzureScriptInternalServerError {
	return &DownloadAzureScriptInternalServerError{}
}

/*
DownloadAzureScriptInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DownloadAzureScriptInternalServerError struct {

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

// IsSuccess returns true when this download azure script internal server error response has a 2xx status code
func (o *DownloadAzureScriptInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this download azure script internal server error response has a 3xx status code
func (o *DownloadAzureScriptInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this download azure script internal server error response has a 4xx status code
func (o *DownloadAzureScriptInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this download azure script internal server error response has a 5xx status code
func (o *DownloadAzureScriptInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this download azure script internal server error response a status code equal to that given
func (o *DownloadAzureScriptInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the download azure script internal server error response
func (o *DownloadAzureScriptInternalServerError) Code() int {
	return 500
}

func (o *DownloadAzureScriptInternalServerError) Error() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptInternalServerError  %+v", 500, o.Payload)
}

func (o *DownloadAzureScriptInternalServerError) String() string {
	return fmt.Sprintf("[GET /cloud-security-registration-azure/entities/scripts/v1][%d] downloadAzureScriptInternalServerError  %+v", 500, o.Payload)
}

func (o *DownloadAzureScriptInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *DownloadAzureScriptInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
