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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// CreateScanReader is a Reader for the CreateScan structure.
type CreateScanReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateScanReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateScanCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewCreateScanForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateScanTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /ods/entities/scans/v1] create-scan", response, response.Code())
	}
}

// NewCreateScanCreated creates a CreateScanCreated with default headers values
func NewCreateScanCreated() *CreateScanCreated {
	return &CreateScanCreated{}
}

/* CreateScanCreated describes a response with status code 201, with default header values.

OK
*/
type CreateScanCreated struct {

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

// IsSuccess returns true when this create scan created response has a 2xx status code
func (o *CreateScanCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create scan created response has a 3xx status code
func (o *CreateScanCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create scan created response has a 4xx status code
func (o *CreateScanCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create scan created response has a 5xx status code
func (o *CreateScanCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create scan created response a status code equal to that given
func (o *CreateScanCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create scan created response
func (o *CreateScanCreated) Code() int {
	return 201
}

func (o *CreateScanCreated) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scans/v1][%d] createScanCreated  %+v", 201, o.Payload)
}

func (o *CreateScanCreated) String() string {
	return fmt.Sprintf("[POST /ods/entities/scans/v1][%d] createScanCreated  %+v", 201, o.Payload)
}

func (o *CreateScanCreated) GetPayload() *models.EntitiesODSScanResponse {
	return o.Payload
}

func (o *CreateScanCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateScanForbidden creates a CreateScanForbidden with default headers values
func NewCreateScanForbidden() *CreateScanForbidden {
	return &CreateScanForbidden{}
}

/* CreateScanForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateScanForbidden struct {

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

// IsSuccess returns true when this create scan forbidden response has a 2xx status code
func (o *CreateScanForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create scan forbidden response has a 3xx status code
func (o *CreateScanForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create scan forbidden response has a 4xx status code
func (o *CreateScanForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create scan forbidden response has a 5xx status code
func (o *CreateScanForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create scan forbidden response a status code equal to that given
func (o *CreateScanForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create scan forbidden response
func (o *CreateScanForbidden) Code() int {
	return 403
}

func (o *CreateScanForbidden) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scans/v1][%d] createScanForbidden  %+v", 403, o.Payload)
}

func (o *CreateScanForbidden) String() string {
	return fmt.Sprintf("[POST /ods/entities/scans/v1][%d] createScanForbidden  %+v", 403, o.Payload)
}

func (o *CreateScanForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateScanForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateScanTooManyRequests creates a CreateScanTooManyRequests with default headers values
func NewCreateScanTooManyRequests() *CreateScanTooManyRequests {
	return &CreateScanTooManyRequests{}
}

/* CreateScanTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateScanTooManyRequests struct {

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

// IsSuccess returns true when this create scan too many requests response has a 2xx status code
func (o *CreateScanTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create scan too many requests response has a 3xx status code
func (o *CreateScanTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create scan too many requests response has a 4xx status code
func (o *CreateScanTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create scan too many requests response has a 5xx status code
func (o *CreateScanTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create scan too many requests response a status code equal to that given
func (o *CreateScanTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create scan too many requests response
func (o *CreateScanTooManyRequests) Code() int {
	return 429
}

func (o *CreateScanTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /ods/entities/scans/v1][%d] createScanTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateScanTooManyRequests) String() string {
	return fmt.Sprintf("[POST /ods/entities/scans/v1][%d] createScanTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateScanTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateScanTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
