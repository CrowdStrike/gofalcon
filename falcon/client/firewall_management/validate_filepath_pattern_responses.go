// Code generated by go-swagger; DO NOT EDIT.

package firewall_management

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

// ValidateFilepathPatternReader is a Reader for the ValidateFilepathPattern structure.
type ValidateFilepathPatternReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ValidateFilepathPatternReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewValidateFilepathPatternOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewValidateFilepathPatternBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewValidateFilepathPatternForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewValidateFilepathPatternTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /fwmgr/entities/rules/validate-filepath/v1] validate-filepath-pattern", response, response.Code())
	}
}

// NewValidateFilepathPatternOK creates a ValidateFilepathPatternOK with default headers values
func NewValidateFilepathPatternOK() *ValidateFilepathPatternOK {
	return &ValidateFilepathPatternOK{}
}

/* ValidateFilepathPatternOK describes a response with status code 200, with default header values.

OK
*/
type ValidateFilepathPatternOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FwmgrAPIValidateFilepathResponse
}

// IsSuccess returns true when this validate filepath pattern o k response has a 2xx status code
func (o *ValidateFilepathPatternOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this validate filepath pattern o k response has a 3xx status code
func (o *ValidateFilepathPatternOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this validate filepath pattern o k response has a 4xx status code
func (o *ValidateFilepathPatternOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this validate filepath pattern o k response has a 5xx status code
func (o *ValidateFilepathPatternOK) IsServerError() bool {
	return false
}

// IsCode returns true when this validate filepath pattern o k response a status code equal to that given
func (o *ValidateFilepathPatternOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the validate filepath pattern o k response
func (o *ValidateFilepathPatternOK) Code() int {
	return 200
}

func (o *ValidateFilepathPatternOK) Error() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternOK  %+v", 200, o.Payload)
}

func (o *ValidateFilepathPatternOK) String() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternOK  %+v", 200, o.Payload)
}

func (o *ValidateFilepathPatternOK) GetPayload() *models.FwmgrAPIValidateFilepathResponse {
	return o.Payload
}

func (o *ValidateFilepathPatternOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FwmgrAPIValidateFilepathResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewValidateFilepathPatternBadRequest creates a ValidateFilepathPatternBadRequest with default headers values
func NewValidateFilepathPatternBadRequest() *ValidateFilepathPatternBadRequest {
	return &ValidateFilepathPatternBadRequest{}
}

/* ValidateFilepathPatternBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ValidateFilepathPatternBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.FwmgrMsaspecResponseFields
}

// IsSuccess returns true when this validate filepath pattern bad request response has a 2xx status code
func (o *ValidateFilepathPatternBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this validate filepath pattern bad request response has a 3xx status code
func (o *ValidateFilepathPatternBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this validate filepath pattern bad request response has a 4xx status code
func (o *ValidateFilepathPatternBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this validate filepath pattern bad request response has a 5xx status code
func (o *ValidateFilepathPatternBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this validate filepath pattern bad request response a status code equal to that given
func (o *ValidateFilepathPatternBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the validate filepath pattern bad request response
func (o *ValidateFilepathPatternBadRequest) Code() int {
	return 400
}

func (o *ValidateFilepathPatternBadRequest) Error() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternBadRequest  %+v", 400, o.Payload)
}

func (o *ValidateFilepathPatternBadRequest) String() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternBadRequest  %+v", 400, o.Payload)
}

func (o *ValidateFilepathPatternBadRequest) GetPayload() *models.FwmgrMsaspecResponseFields {
	return o.Payload
}

func (o *ValidateFilepathPatternBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.FwmgrMsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewValidateFilepathPatternForbidden creates a ValidateFilepathPatternForbidden with default headers values
func NewValidateFilepathPatternForbidden() *ValidateFilepathPatternForbidden {
	return &ValidateFilepathPatternForbidden{}
}

/* ValidateFilepathPatternForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ValidateFilepathPatternForbidden struct {

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

// IsSuccess returns true when this validate filepath pattern forbidden response has a 2xx status code
func (o *ValidateFilepathPatternForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this validate filepath pattern forbidden response has a 3xx status code
func (o *ValidateFilepathPatternForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this validate filepath pattern forbidden response has a 4xx status code
func (o *ValidateFilepathPatternForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this validate filepath pattern forbidden response has a 5xx status code
func (o *ValidateFilepathPatternForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this validate filepath pattern forbidden response a status code equal to that given
func (o *ValidateFilepathPatternForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the validate filepath pattern forbidden response
func (o *ValidateFilepathPatternForbidden) Code() int {
	return 403
}

func (o *ValidateFilepathPatternForbidden) Error() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternForbidden  %+v", 403, o.Payload)
}

func (o *ValidateFilepathPatternForbidden) String() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternForbidden  %+v", 403, o.Payload)
}

func (o *ValidateFilepathPatternForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ValidateFilepathPatternForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewValidateFilepathPatternTooManyRequests creates a ValidateFilepathPatternTooManyRequests with default headers values
func NewValidateFilepathPatternTooManyRequests() *ValidateFilepathPatternTooManyRequests {
	return &ValidateFilepathPatternTooManyRequests{}
}

/* ValidateFilepathPatternTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ValidateFilepathPatternTooManyRequests struct {

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

// IsSuccess returns true when this validate filepath pattern too many requests response has a 2xx status code
func (o *ValidateFilepathPatternTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this validate filepath pattern too many requests response has a 3xx status code
func (o *ValidateFilepathPatternTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this validate filepath pattern too many requests response has a 4xx status code
func (o *ValidateFilepathPatternTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this validate filepath pattern too many requests response has a 5xx status code
func (o *ValidateFilepathPatternTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this validate filepath pattern too many requests response a status code equal to that given
func (o *ValidateFilepathPatternTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the validate filepath pattern too many requests response
func (o *ValidateFilepathPatternTooManyRequests) Code() int {
	return 429
}

func (o *ValidateFilepathPatternTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternTooManyRequests  %+v", 429, o.Payload)
}

func (o *ValidateFilepathPatternTooManyRequests) String() string {
	return fmt.Sprintf("[POST /fwmgr/entities/rules/validate-filepath/v1][%d] validateFilepathPatternTooManyRequests  %+v", 429, o.Payload)
}

func (o *ValidateFilepathPatternTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ValidateFilepathPatternTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
