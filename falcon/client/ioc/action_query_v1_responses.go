// Code generated by go-swagger; DO NOT EDIT.

package ioc

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

// ActionQueryV1Reader is a Reader for the ActionQueryV1 structure.
type ActionQueryV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ActionQueryV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewActionQueryV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewActionQueryV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewActionQueryV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /iocs/queries/actions/v1] action.query.v1", response, response.Code())
	}
}

// NewActionQueryV1OK creates a ActionQueryV1OK with default headers values
func NewActionQueryV1OK() *ActionQueryV1OK {
	return &ActionQueryV1OK{}
}

/*
ActionQueryV1OK describes a response with status code 200, with default header values.

OK
*/
type ActionQueryV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIIndicatorQueryRespV1
}

// IsSuccess returns true when this action query v1 o k response has a 2xx status code
func (o *ActionQueryV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this action query v1 o k response has a 3xx status code
func (o *ActionQueryV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this action query v1 o k response has a 4xx status code
func (o *ActionQueryV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this action query v1 o k response has a 5xx status code
func (o *ActionQueryV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this action query v1 o k response a status code equal to that given
func (o *ActionQueryV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the action query v1 o k response
func (o *ActionQueryV1OK) Code() int {
	return 200
}

func (o *ActionQueryV1OK) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/actions/v1][%d] actionQueryV1OK  %+v", 200, o.Payload)
}

func (o *ActionQueryV1OK) String() string {
	return fmt.Sprintf("[GET /iocs/queries/actions/v1][%d] actionQueryV1OK  %+v", 200, o.Payload)
}

func (o *ActionQueryV1OK) GetPayload() *models.APIIndicatorQueryRespV1 {
	return o.Payload
}

func (o *ActionQueryV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIIndicatorQueryRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActionQueryV1Forbidden creates a ActionQueryV1Forbidden with default headers values
func NewActionQueryV1Forbidden() *ActionQueryV1Forbidden {
	return &ActionQueryV1Forbidden{}
}

/*
ActionQueryV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ActionQueryV1Forbidden struct {

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

// IsSuccess returns true when this action query v1 forbidden response has a 2xx status code
func (o *ActionQueryV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this action query v1 forbidden response has a 3xx status code
func (o *ActionQueryV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this action query v1 forbidden response has a 4xx status code
func (o *ActionQueryV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this action query v1 forbidden response has a 5xx status code
func (o *ActionQueryV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this action query v1 forbidden response a status code equal to that given
func (o *ActionQueryV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the action query v1 forbidden response
func (o *ActionQueryV1Forbidden) Code() int {
	return 403
}

func (o *ActionQueryV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/actions/v1][%d] actionQueryV1Forbidden  %+v", 403, o.Payload)
}

func (o *ActionQueryV1Forbidden) String() string {
	return fmt.Sprintf("[GET /iocs/queries/actions/v1][%d] actionQueryV1Forbidden  %+v", 403, o.Payload)
}

func (o *ActionQueryV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ActionQueryV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewActionQueryV1TooManyRequests creates a ActionQueryV1TooManyRequests with default headers values
func NewActionQueryV1TooManyRequests() *ActionQueryV1TooManyRequests {
	return &ActionQueryV1TooManyRequests{}
}

/*
ActionQueryV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ActionQueryV1TooManyRequests struct {

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

// IsSuccess returns true when this action query v1 too many requests response has a 2xx status code
func (o *ActionQueryV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this action query v1 too many requests response has a 3xx status code
func (o *ActionQueryV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this action query v1 too many requests response has a 4xx status code
func (o *ActionQueryV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this action query v1 too many requests response has a 5xx status code
func (o *ActionQueryV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this action query v1 too many requests response a status code equal to that given
func (o *ActionQueryV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the action query v1 too many requests response
func (o *ActionQueryV1TooManyRequests) Code() int {
	return 429
}

func (o *ActionQueryV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /iocs/queries/actions/v1][%d] actionQueryV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *ActionQueryV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /iocs/queries/actions/v1][%d] actionQueryV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *ActionQueryV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ActionQueryV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
