// Code generated by go-swagger; DO NOT EDIT.

package d4c_registration

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

// GetHorizonD4CScriptsReader is a Reader for the GetHorizonD4CScripts structure.
type GetHorizonD4CScriptsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetHorizonD4CScriptsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetHorizonD4CScriptsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetHorizonD4CScriptsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetHorizonD4CScriptsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /settings-discover/entities/gen/scripts/v1] GetHorizonD4CScripts", response, response.Code())
	}
}

// NewGetHorizonD4CScriptsOK creates a GetHorizonD4CScriptsOK with default headers values
func NewGetHorizonD4CScriptsOK() *GetHorizonD4CScriptsOK {
	return &GetHorizonD4CScriptsOK{}
}

/* GetHorizonD4CScriptsOK describes a response with status code 200, with default header values.

OK
*/
type GetHorizonD4CScriptsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationStaticScriptsResponse
}

// IsSuccess returns true when this get horizon d4 c scripts o k response has a 2xx status code
func (o *GetHorizonD4CScriptsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get horizon d4 c scripts o k response has a 3xx status code
func (o *GetHorizonD4CScriptsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get horizon d4 c scripts o k response has a 4xx status code
func (o *GetHorizonD4CScriptsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get horizon d4 c scripts o k response has a 5xx status code
func (o *GetHorizonD4CScriptsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get horizon d4 c scripts o k response a status code equal to that given
func (o *GetHorizonD4CScriptsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get horizon d4 c scripts o k response
func (o *GetHorizonD4CScriptsOK) Code() int {
	return 200
}

func (o *GetHorizonD4CScriptsOK) Error() string {
	return fmt.Sprintf("[GET /settings-discover/entities/gen/scripts/v1][%d] getHorizonD4CScriptsOK  %+v", 200, o.Payload)
}

func (o *GetHorizonD4CScriptsOK) String() string {
	return fmt.Sprintf("[GET /settings-discover/entities/gen/scripts/v1][%d] getHorizonD4CScriptsOK  %+v", 200, o.Payload)
}

func (o *GetHorizonD4CScriptsOK) GetPayload() *models.RegistrationStaticScriptsResponse {
	return o.Payload
}

func (o *GetHorizonD4CScriptsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationStaticScriptsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetHorizonD4CScriptsForbidden creates a GetHorizonD4CScriptsForbidden with default headers values
func NewGetHorizonD4CScriptsForbidden() *GetHorizonD4CScriptsForbidden {
	return &GetHorizonD4CScriptsForbidden{}
}

/* GetHorizonD4CScriptsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetHorizonD4CScriptsForbidden struct {

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

// IsSuccess returns true when this get horizon d4 c scripts forbidden response has a 2xx status code
func (o *GetHorizonD4CScriptsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get horizon d4 c scripts forbidden response has a 3xx status code
func (o *GetHorizonD4CScriptsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get horizon d4 c scripts forbidden response has a 4xx status code
func (o *GetHorizonD4CScriptsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get horizon d4 c scripts forbidden response has a 5xx status code
func (o *GetHorizonD4CScriptsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get horizon d4 c scripts forbidden response a status code equal to that given
func (o *GetHorizonD4CScriptsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get horizon d4 c scripts forbidden response
func (o *GetHorizonD4CScriptsForbidden) Code() int {
	return 403
}

func (o *GetHorizonD4CScriptsForbidden) Error() string {
	return fmt.Sprintf("[GET /settings-discover/entities/gen/scripts/v1][%d] getHorizonD4CScriptsForbidden  %+v", 403, o.Payload)
}

func (o *GetHorizonD4CScriptsForbidden) String() string {
	return fmt.Sprintf("[GET /settings-discover/entities/gen/scripts/v1][%d] getHorizonD4CScriptsForbidden  %+v", 403, o.Payload)
}

func (o *GetHorizonD4CScriptsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetHorizonD4CScriptsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetHorizonD4CScriptsTooManyRequests creates a GetHorizonD4CScriptsTooManyRequests with default headers values
func NewGetHorizonD4CScriptsTooManyRequests() *GetHorizonD4CScriptsTooManyRequests {
	return &GetHorizonD4CScriptsTooManyRequests{}
}

/* GetHorizonD4CScriptsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetHorizonD4CScriptsTooManyRequests struct {

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

// IsSuccess returns true when this get horizon d4 c scripts too many requests response has a 2xx status code
func (o *GetHorizonD4CScriptsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get horizon d4 c scripts too many requests response has a 3xx status code
func (o *GetHorizonD4CScriptsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get horizon d4 c scripts too many requests response has a 4xx status code
func (o *GetHorizonD4CScriptsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get horizon d4 c scripts too many requests response has a 5xx status code
func (o *GetHorizonD4CScriptsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get horizon d4 c scripts too many requests response a status code equal to that given
func (o *GetHorizonD4CScriptsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get horizon d4 c scripts too many requests response
func (o *GetHorizonD4CScriptsTooManyRequests) Code() int {
	return 429
}

func (o *GetHorizonD4CScriptsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /settings-discover/entities/gen/scripts/v1][%d] getHorizonD4CScriptsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetHorizonD4CScriptsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /settings-discover/entities/gen/scripts/v1][%d] getHorizonD4CScriptsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetHorizonD4CScriptsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetHorizonD4CScriptsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
