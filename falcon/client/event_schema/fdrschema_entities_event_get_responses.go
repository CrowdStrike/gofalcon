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

// FdrschemaEntitiesEventGetReader is a Reader for the FdrschemaEntitiesEventGet structure.
type FdrschemaEntitiesEventGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *FdrschemaEntitiesEventGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewFdrschemaEntitiesEventGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewFdrschemaEntitiesEventGetForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewFdrschemaEntitiesEventGetTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /fdr/entities/schema-events/v1] fdrschema.entities.event.get", response, response.Code())
	}
}

// NewFdrschemaEntitiesEventGetOK creates a FdrschemaEntitiesEventGetOK with default headers values
func NewFdrschemaEntitiesEventGetOK() *FdrschemaEntitiesEventGetOK {
	return &FdrschemaEntitiesEventGetOK{}
}

/* FdrschemaEntitiesEventGetOK describes a response with status code 200, with default header values.

OK
*/
type FdrschemaEntitiesEventGetOK struct {

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

// IsSuccess returns true when this fdrschema entities event get o k response has a 2xx status code
func (o *FdrschemaEntitiesEventGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this fdrschema entities event get o k response has a 3xx status code
func (o *FdrschemaEntitiesEventGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdrschema entities event get o k response has a 4xx status code
func (o *FdrschemaEntitiesEventGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this fdrschema entities event get o k response has a 5xx status code
func (o *FdrschemaEntitiesEventGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this fdrschema entities event get o k response a status code equal to that given
func (o *FdrschemaEntitiesEventGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the fdrschema entities event get o k response
func (o *FdrschemaEntitiesEventGetOK) Code() int {
	return 200
}

func (o *FdrschemaEntitiesEventGetOK) Error() string {
	return fmt.Sprintf("[GET /fdr/entities/schema-events/v1][%d] fdrschemaEntitiesEventGetOK  %+v", 200, o.Payload)
}

func (o *FdrschemaEntitiesEventGetOK) String() string {
	return fmt.Sprintf("[GET /fdr/entities/schema-events/v1][%d] fdrschemaEntitiesEventGetOK  %+v", 200, o.Payload)
}

func (o *FdrschemaEntitiesEventGetOK) GetPayload() *models.SchemaSensorEventResponseV1 {
	return o.Payload
}

func (o *FdrschemaEntitiesEventGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewFdrschemaEntitiesEventGetForbidden creates a FdrschemaEntitiesEventGetForbidden with default headers values
func NewFdrschemaEntitiesEventGetForbidden() *FdrschemaEntitiesEventGetForbidden {
	return &FdrschemaEntitiesEventGetForbidden{}
}

/* FdrschemaEntitiesEventGetForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type FdrschemaEntitiesEventGetForbidden struct {

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

// IsSuccess returns true when this fdrschema entities event get forbidden response has a 2xx status code
func (o *FdrschemaEntitiesEventGetForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdrschema entities event get forbidden response has a 3xx status code
func (o *FdrschemaEntitiesEventGetForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdrschema entities event get forbidden response has a 4xx status code
func (o *FdrschemaEntitiesEventGetForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdrschema entities event get forbidden response has a 5xx status code
func (o *FdrschemaEntitiesEventGetForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this fdrschema entities event get forbidden response a status code equal to that given
func (o *FdrschemaEntitiesEventGetForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the fdrschema entities event get forbidden response
func (o *FdrschemaEntitiesEventGetForbidden) Code() int {
	return 403
}

func (o *FdrschemaEntitiesEventGetForbidden) Error() string {
	return fmt.Sprintf("[GET /fdr/entities/schema-events/v1][%d] fdrschemaEntitiesEventGetForbidden  %+v", 403, o.Payload)
}

func (o *FdrschemaEntitiesEventGetForbidden) String() string {
	return fmt.Sprintf("[GET /fdr/entities/schema-events/v1][%d] fdrschemaEntitiesEventGetForbidden  %+v", 403, o.Payload)
}

func (o *FdrschemaEntitiesEventGetForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *FdrschemaEntitiesEventGetForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewFdrschemaEntitiesEventGetTooManyRequests creates a FdrschemaEntitiesEventGetTooManyRequests with default headers values
func NewFdrschemaEntitiesEventGetTooManyRequests() *FdrschemaEntitiesEventGetTooManyRequests {
	return &FdrschemaEntitiesEventGetTooManyRequests{}
}

/* FdrschemaEntitiesEventGetTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type FdrschemaEntitiesEventGetTooManyRequests struct {

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

// IsSuccess returns true when this fdrschema entities event get too many requests response has a 2xx status code
func (o *FdrschemaEntitiesEventGetTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdrschema entities event get too many requests response has a 3xx status code
func (o *FdrschemaEntitiesEventGetTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdrschema entities event get too many requests response has a 4xx status code
func (o *FdrschemaEntitiesEventGetTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdrschema entities event get too many requests response has a 5xx status code
func (o *FdrschemaEntitiesEventGetTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this fdrschema entities event get too many requests response a status code equal to that given
func (o *FdrschemaEntitiesEventGetTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the fdrschema entities event get too many requests response
func (o *FdrschemaEntitiesEventGetTooManyRequests) Code() int {
	return 429
}

func (o *FdrschemaEntitiesEventGetTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /fdr/entities/schema-events/v1][%d] fdrschemaEntitiesEventGetTooManyRequests  %+v", 429, o.Payload)
}

func (o *FdrschemaEntitiesEventGetTooManyRequests) String() string {
	return fmt.Sprintf("[GET /fdr/entities/schema-events/v1][%d] fdrschemaEntitiesEventGetTooManyRequests  %+v", 429, o.Payload)
}

func (o *FdrschemaEntitiesEventGetTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *FdrschemaEntitiesEventGetTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
