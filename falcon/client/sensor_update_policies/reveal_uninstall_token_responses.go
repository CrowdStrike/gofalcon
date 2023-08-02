// Code generated by go-swagger; DO NOT EDIT.

package sensor_update_policies

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

// RevealUninstallTokenReader is a Reader for the RevealUninstallToken structure.
type RevealUninstallTokenReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevealUninstallTokenReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevealUninstallTokenOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRevealUninstallTokenBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevealUninstallTokenForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevealUninstallTokenTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewRevealUninstallTokenInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /policy/combined/reveal-uninstall-token/v1] revealUninstallToken", response, response.Code())
	}
}

// NewRevealUninstallTokenOK creates a RevealUninstallTokenOK with default headers values
func NewRevealUninstallTokenOK() *RevealUninstallTokenOK {
	return &RevealUninstallTokenOK{}
}

/*
RevealUninstallTokenOK describes a response with status code 200, with default header values.

OK
*/
type RevealUninstallTokenOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.UninstallTokenRespV1
}

// IsSuccess returns true when this reveal uninstall token o k response has a 2xx status code
func (o *RevealUninstallTokenOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reveal uninstall token o k response has a 3xx status code
func (o *RevealUninstallTokenOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reveal uninstall token o k response has a 4xx status code
func (o *RevealUninstallTokenOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reveal uninstall token o k response has a 5xx status code
func (o *RevealUninstallTokenOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reveal uninstall token o k response a status code equal to that given
func (o *RevealUninstallTokenOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reveal uninstall token o k response
func (o *RevealUninstallTokenOK) Code() int {
	return 200
}

func (o *RevealUninstallTokenOK) Error() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenOK  %+v", 200, o.Payload)
}

func (o *RevealUninstallTokenOK) String() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenOK  %+v", 200, o.Payload)
}

func (o *RevealUninstallTokenOK) GetPayload() *models.UninstallTokenRespV1 {
	return o.Payload
}

func (o *RevealUninstallTokenOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.UninstallTokenRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevealUninstallTokenBadRequest creates a RevealUninstallTokenBadRequest with default headers values
func NewRevealUninstallTokenBadRequest() *RevealUninstallTokenBadRequest {
	return &RevealUninstallTokenBadRequest{}
}

/*
RevealUninstallTokenBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type RevealUninstallTokenBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.UninstallTokenRespV1
}

// IsSuccess returns true when this reveal uninstall token bad request response has a 2xx status code
func (o *RevealUninstallTokenBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reveal uninstall token bad request response has a 3xx status code
func (o *RevealUninstallTokenBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reveal uninstall token bad request response has a 4xx status code
func (o *RevealUninstallTokenBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this reveal uninstall token bad request response has a 5xx status code
func (o *RevealUninstallTokenBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this reveal uninstall token bad request response a status code equal to that given
func (o *RevealUninstallTokenBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the reveal uninstall token bad request response
func (o *RevealUninstallTokenBadRequest) Code() int {
	return 400
}

func (o *RevealUninstallTokenBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenBadRequest  %+v", 400, o.Payload)
}

func (o *RevealUninstallTokenBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenBadRequest  %+v", 400, o.Payload)
}

func (o *RevealUninstallTokenBadRequest) GetPayload() *models.UninstallTokenRespV1 {
	return o.Payload
}

func (o *RevealUninstallTokenBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.UninstallTokenRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevealUninstallTokenForbidden creates a RevealUninstallTokenForbidden with default headers values
func NewRevealUninstallTokenForbidden() *RevealUninstallTokenForbidden {
	return &RevealUninstallTokenForbidden{}
}

/*
RevealUninstallTokenForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevealUninstallTokenForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this reveal uninstall token forbidden response has a 2xx status code
func (o *RevealUninstallTokenForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reveal uninstall token forbidden response has a 3xx status code
func (o *RevealUninstallTokenForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reveal uninstall token forbidden response has a 4xx status code
func (o *RevealUninstallTokenForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reveal uninstall token forbidden response has a 5xx status code
func (o *RevealUninstallTokenForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reveal uninstall token forbidden response a status code equal to that given
func (o *RevealUninstallTokenForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reveal uninstall token forbidden response
func (o *RevealUninstallTokenForbidden) Code() int {
	return 403
}

func (o *RevealUninstallTokenForbidden) Error() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenForbidden  %+v", 403, o.Payload)
}

func (o *RevealUninstallTokenForbidden) String() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenForbidden  %+v", 403, o.Payload)
}

func (o *RevealUninstallTokenForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *RevealUninstallTokenForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevealUninstallTokenTooManyRequests creates a RevealUninstallTokenTooManyRequests with default headers values
func NewRevealUninstallTokenTooManyRequests() *RevealUninstallTokenTooManyRequests {
	return &RevealUninstallTokenTooManyRequests{}
}

/*
RevealUninstallTokenTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type RevealUninstallTokenTooManyRequests struct {

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

// IsSuccess returns true when this reveal uninstall token too many requests response has a 2xx status code
func (o *RevealUninstallTokenTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reveal uninstall token too many requests response has a 3xx status code
func (o *RevealUninstallTokenTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reveal uninstall token too many requests response has a 4xx status code
func (o *RevealUninstallTokenTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reveal uninstall token too many requests response has a 5xx status code
func (o *RevealUninstallTokenTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reveal uninstall token too many requests response a status code equal to that given
func (o *RevealUninstallTokenTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reveal uninstall token too many requests response
func (o *RevealUninstallTokenTooManyRequests) Code() int {
	return 429
}

func (o *RevealUninstallTokenTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevealUninstallTokenTooManyRequests) String() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevealUninstallTokenTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *RevealUninstallTokenTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewRevealUninstallTokenInternalServerError creates a RevealUninstallTokenInternalServerError with default headers values
func NewRevealUninstallTokenInternalServerError() *RevealUninstallTokenInternalServerError {
	return &RevealUninstallTokenInternalServerError{}
}

/*
RevealUninstallTokenInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type RevealUninstallTokenInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.UninstallTokenRespV1
}

// IsSuccess returns true when this reveal uninstall token internal server error response has a 2xx status code
func (o *RevealUninstallTokenInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reveal uninstall token internal server error response has a 3xx status code
func (o *RevealUninstallTokenInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reveal uninstall token internal server error response has a 4xx status code
func (o *RevealUninstallTokenInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this reveal uninstall token internal server error response has a 5xx status code
func (o *RevealUninstallTokenInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this reveal uninstall token internal server error response a status code equal to that given
func (o *RevealUninstallTokenInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the reveal uninstall token internal server error response
func (o *RevealUninstallTokenInternalServerError) Code() int {
	return 500
}

func (o *RevealUninstallTokenInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenInternalServerError  %+v", 500, o.Payload)
}

func (o *RevealUninstallTokenInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/combined/reveal-uninstall-token/v1][%d] revealUninstallTokenInternalServerError  %+v", 500, o.Payload)
}

func (o *RevealUninstallTokenInternalServerError) GetPayload() *models.UninstallTokenRespV1 {
	return o.Payload
}

func (o *RevealUninstallTokenInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.UninstallTokenRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
