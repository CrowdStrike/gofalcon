// Code generated by go-swagger; DO NOT EDIT.

package custom_storage

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

// GetObjectReader is a Reader for the GetObject structure.
type GetObjectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetObjectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetObjectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetObjectForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetObjectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}] GetObject", response, response.Code())
	}
}

// NewGetObjectOK creates a GetObjectOK with default headers values
func NewGetObjectOK() *GetObjectOK {
	return &GetObjectOK{}
}

/*
GetObjectOK describes a response with status code 200, with default header values.

OK
*/
type GetObjectOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload []int64
}

// IsSuccess returns true when this get object o k response has a 2xx status code
func (o *GetObjectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get object o k response has a 3xx status code
func (o *GetObjectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get object o k response has a 4xx status code
func (o *GetObjectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get object o k response has a 5xx status code
func (o *GetObjectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get object o k response a status code equal to that given
func (o *GetObjectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get object o k response
func (o *GetObjectOK) Code() int {
	return 200
}

func (o *GetObjectOK) Error() string {
	return fmt.Sprintf("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] getObjectOK  %+v", 200, o.Payload)
}

func (o *GetObjectOK) String() string {
	return fmt.Sprintf("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] getObjectOK  %+v", 200, o.Payload)
}

func (o *GetObjectOK) GetPayload() []int64 {
	return o.Payload
}

func (o *GetObjectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetObjectForbidden creates a GetObjectForbidden with default headers values
func NewGetObjectForbidden() *GetObjectForbidden {
	return &GetObjectForbidden{}
}

/*
GetObjectForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetObjectForbidden struct {

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

// IsSuccess returns true when this get object forbidden response has a 2xx status code
func (o *GetObjectForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get object forbidden response has a 3xx status code
func (o *GetObjectForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get object forbidden response has a 4xx status code
func (o *GetObjectForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get object forbidden response has a 5xx status code
func (o *GetObjectForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get object forbidden response a status code equal to that given
func (o *GetObjectForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get object forbidden response
func (o *GetObjectForbidden) Code() int {
	return 403
}

func (o *GetObjectForbidden) Error() string {
	return fmt.Sprintf("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] getObjectForbidden  %+v", 403, o.Payload)
}

func (o *GetObjectForbidden) String() string {
	return fmt.Sprintf("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] getObjectForbidden  %+v", 403, o.Payload)
}

func (o *GetObjectForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetObjectForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetObjectTooManyRequests creates a GetObjectTooManyRequests with default headers values
func NewGetObjectTooManyRequests() *GetObjectTooManyRequests {
	return &GetObjectTooManyRequests{}
}

/*
GetObjectTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetObjectTooManyRequests struct {

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

// IsSuccess returns true when this get object too many requests response has a 2xx status code
func (o *GetObjectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get object too many requests response has a 3xx status code
func (o *GetObjectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get object too many requests response has a 4xx status code
func (o *GetObjectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get object too many requests response has a 5xx status code
func (o *GetObjectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get object too many requests response a status code equal to that given
func (o *GetObjectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get object too many requests response
func (o *GetObjectTooManyRequests) Code() int {
	return 429
}

func (o *GetObjectTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] getObjectTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetObjectTooManyRequests) String() string {
	return fmt.Sprintf("[GET /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] getObjectTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetObjectTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetObjectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
