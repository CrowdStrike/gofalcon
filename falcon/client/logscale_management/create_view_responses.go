// Code generated by go-swagger; DO NOT EDIT.

package logscale_management

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

// CreateViewReader is a Reader for the CreateView structure.
type CreateViewReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateViewReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateViewOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewCreateViewForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateViewTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /loggingapi/entities/views/v1] CreateView", response, response.Code())
	}
}

// NewCreateViewOK creates a CreateViewOK with default headers values
func NewCreateViewOK() *CreateViewOK {
	return &CreateViewOK{}
}

/* CreateViewOK describes a response with status code 200, with default header values.

OK
*/
type CreateViewOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.HumioViewWrapper
}

// IsSuccess returns true when this create view o k response has a 2xx status code
func (o *CreateViewOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create view o k response has a 3xx status code
func (o *CreateViewOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create view o k response has a 4xx status code
func (o *CreateViewOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create view o k response has a 5xx status code
func (o *CreateViewOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create view o k response a status code equal to that given
func (o *CreateViewOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create view o k response
func (o *CreateViewOK) Code() int {
	return 200
}

func (o *CreateViewOK) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewOK  %+v", 200, o.Payload)
}

func (o *CreateViewOK) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewOK  %+v", 200, o.Payload)
}

func (o *CreateViewOK) GetPayload() *models.HumioViewWrapper {
	return o.Payload
}

func (o *CreateViewOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.HumioViewWrapper)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateViewForbidden creates a CreateViewForbidden with default headers values
func NewCreateViewForbidden() *CreateViewForbidden {
	return &CreateViewForbidden{}
}

/* CreateViewForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateViewForbidden struct {

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

// IsSuccess returns true when this create view forbidden response has a 2xx status code
func (o *CreateViewForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create view forbidden response has a 3xx status code
func (o *CreateViewForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create view forbidden response has a 4xx status code
func (o *CreateViewForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create view forbidden response has a 5xx status code
func (o *CreateViewForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create view forbidden response a status code equal to that given
func (o *CreateViewForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create view forbidden response
func (o *CreateViewForbidden) Code() int {
	return 403
}

func (o *CreateViewForbidden) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewForbidden  %+v", 403, o.Payload)
}

func (o *CreateViewForbidden) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewForbidden  %+v", 403, o.Payload)
}

func (o *CreateViewForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateViewForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateViewTooManyRequests creates a CreateViewTooManyRequests with default headers values
func NewCreateViewTooManyRequests() *CreateViewTooManyRequests {
	return &CreateViewTooManyRequests{}
}

/* CreateViewTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateViewTooManyRequests struct {

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

// IsSuccess returns true when this create view too many requests response has a 2xx status code
func (o *CreateViewTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create view too many requests response has a 3xx status code
func (o *CreateViewTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create view too many requests response has a 4xx status code
func (o *CreateViewTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create view too many requests response has a 5xx status code
func (o *CreateViewTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create view too many requests response a status code equal to that given
func (o *CreateViewTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create view too many requests response
func (o *CreateViewTooManyRequests) Code() int {
	return 429
}

func (o *CreateViewTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateViewTooManyRequests) String() string {
	return fmt.Sprintf("[POST /loggingapi/entities/views/v1][%d] createViewTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateViewTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateViewTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
