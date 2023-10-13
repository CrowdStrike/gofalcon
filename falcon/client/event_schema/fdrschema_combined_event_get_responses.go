// Code generated by go-swagger; DO NOT EDIT.

package event_schema

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

// FdrschemaCombinedEventGetReader is a Reader for the FdrschemaCombinedEventGet structure.
type FdrschemaCombinedEventGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *FdrschemaCombinedEventGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewFdrschemaCombinedEventGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewFdrschemaCombinedEventGetForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewFdrschemaCombinedEventGetTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /fdr/combined/schema-members/v1] fdrschema.combined.event.get", response, response.Code())
	}
}

// NewFdrschemaCombinedEventGetOK creates a FdrschemaCombinedEventGetOK with default headers values
func NewFdrschemaCombinedEventGetOK() *FdrschemaCombinedEventGetOK {
	return &FdrschemaCombinedEventGetOK{}
}

/* FdrschemaCombinedEventGetOK describes a response with status code 200, with default header values.

OK
*/
type FdrschemaCombinedEventGetOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.SchemaSensorEventResponseV1
}

// IsSuccess returns true when this fdrschema combined event get o k response has a 2xx status code
func (o *FdrschemaCombinedEventGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this fdrschema combined event get o k response has a 3xx status code
func (o *FdrschemaCombinedEventGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdrschema combined event get o k response has a 4xx status code
func (o *FdrschemaCombinedEventGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this fdrschema combined event get o k response has a 5xx status code
func (o *FdrschemaCombinedEventGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this fdrschema combined event get o k response a status code equal to that given
func (o *FdrschemaCombinedEventGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the fdrschema combined event get o k response
func (o *FdrschemaCombinedEventGetOK) Code() int {
	return 200
}

func (o *FdrschemaCombinedEventGetOK) Error() string {
	return fmt.Sprintf("[GET /fdr/combined/schema-members/v1][%d] fdrschemaCombinedEventGetOK  %+v", 200, o.Payload)
}

func (o *FdrschemaCombinedEventGetOK) String() string {
	return fmt.Sprintf("[GET /fdr/combined/schema-members/v1][%d] fdrschemaCombinedEventGetOK  %+v", 200, o.Payload)
}

func (o *FdrschemaCombinedEventGetOK) GetPayload() *models.SchemaSensorEventResponseV1 {
	return o.Payload
}

func (o *FdrschemaCombinedEventGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.SchemaSensorEventResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFdrschemaCombinedEventGetForbidden creates a FdrschemaCombinedEventGetForbidden with default headers values
func NewFdrschemaCombinedEventGetForbidden() *FdrschemaCombinedEventGetForbidden {
	return &FdrschemaCombinedEventGetForbidden{}
}

/* FdrschemaCombinedEventGetForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type FdrschemaCombinedEventGetForbidden struct {

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

// IsSuccess returns true when this fdrschema combined event get forbidden response has a 2xx status code
func (o *FdrschemaCombinedEventGetForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdrschema combined event get forbidden response has a 3xx status code
func (o *FdrschemaCombinedEventGetForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdrschema combined event get forbidden response has a 4xx status code
func (o *FdrschemaCombinedEventGetForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdrschema combined event get forbidden response has a 5xx status code
func (o *FdrschemaCombinedEventGetForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this fdrschema combined event get forbidden response a status code equal to that given
func (o *FdrschemaCombinedEventGetForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the fdrschema combined event get forbidden response
func (o *FdrschemaCombinedEventGetForbidden) Code() int {
	return 403
}

func (o *FdrschemaCombinedEventGetForbidden) Error() string {
	return fmt.Sprintf("[GET /fdr/combined/schema-members/v1][%d] fdrschemaCombinedEventGetForbidden  %+v", 403, o.Payload)
}

func (o *FdrschemaCombinedEventGetForbidden) String() string {
	return fmt.Sprintf("[GET /fdr/combined/schema-members/v1][%d] fdrschemaCombinedEventGetForbidden  %+v", 403, o.Payload)
}

func (o *FdrschemaCombinedEventGetForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *FdrschemaCombinedEventGetForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewFdrschemaCombinedEventGetTooManyRequests creates a FdrschemaCombinedEventGetTooManyRequests with default headers values
func NewFdrschemaCombinedEventGetTooManyRequests() *FdrschemaCombinedEventGetTooManyRequests {
	return &FdrschemaCombinedEventGetTooManyRequests{}
}

/* FdrschemaCombinedEventGetTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type FdrschemaCombinedEventGetTooManyRequests struct {

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

// IsSuccess returns true when this fdrschema combined event get too many requests response has a 2xx status code
func (o *FdrschemaCombinedEventGetTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdrschema combined event get too many requests response has a 3xx status code
func (o *FdrschemaCombinedEventGetTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdrschema combined event get too many requests response has a 4xx status code
func (o *FdrschemaCombinedEventGetTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdrschema combined event get too many requests response has a 5xx status code
func (o *FdrschemaCombinedEventGetTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this fdrschema combined event get too many requests response a status code equal to that given
func (o *FdrschemaCombinedEventGetTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the fdrschema combined event get too many requests response
func (o *FdrschemaCombinedEventGetTooManyRequests) Code() int {
	return 429
}

func (o *FdrschemaCombinedEventGetTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /fdr/combined/schema-members/v1][%d] fdrschemaCombinedEventGetTooManyRequests  %+v", 429, o.Payload)
}

func (o *FdrschemaCombinedEventGetTooManyRequests) String() string {
	return fmt.Sprintf("[GET /fdr/combined/schema-members/v1][%d] fdrschemaCombinedEventGetTooManyRequests  %+v", 429, o.Payload)
}

func (o *FdrschemaCombinedEventGetTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *FdrschemaCombinedEventGetTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
