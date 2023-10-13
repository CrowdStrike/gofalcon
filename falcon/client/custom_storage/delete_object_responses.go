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

// DeleteObjectReader is a Reader for the DeleteObject structure.
type DeleteObjectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteObjectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteObjectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewDeleteObjectForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteObjectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}] DeleteObject", response, response.Code())
	}
}

// NewDeleteObjectOK creates a DeleteObjectOK with default headers values
func NewDeleteObjectOK() *DeleteObjectOK {
	return &DeleteObjectOK{}
}

/* DeleteObjectOK describes a response with status code 200, with default header values.

OK
*/
type DeleteObjectOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CustomType4078359637
}

// IsSuccess returns true when this delete object o k response has a 2xx status code
func (o *DeleteObjectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete object o k response has a 3xx status code
func (o *DeleteObjectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete object o k response has a 4xx status code
func (o *DeleteObjectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete object o k response has a 5xx status code
func (o *DeleteObjectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete object o k response a status code equal to that given
func (o *DeleteObjectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete object o k response
func (o *DeleteObjectOK) Code() int {
	return 200
}

func (o *DeleteObjectOK) Error() string {
	return fmt.Sprintf("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] deleteObjectOK  %+v", 200, o.Payload)
}

func (o *DeleteObjectOK) String() string {
	return fmt.Sprintf("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] deleteObjectOK  %+v", 200, o.Payload)
}

func (o *DeleteObjectOK) GetPayload() *models.CustomType4078359637 {
	return o.Payload
}

func (o *DeleteObjectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CustomType4078359637)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteObjectForbidden creates a DeleteObjectForbidden with default headers values
func NewDeleteObjectForbidden() *DeleteObjectForbidden {
	return &DeleteObjectForbidden{}
}

/* DeleteObjectForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteObjectForbidden struct {

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

// IsSuccess returns true when this delete object forbidden response has a 2xx status code
func (o *DeleteObjectForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete object forbidden response has a 3xx status code
func (o *DeleteObjectForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete object forbidden response has a 4xx status code
func (o *DeleteObjectForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete object forbidden response has a 5xx status code
func (o *DeleteObjectForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete object forbidden response a status code equal to that given
func (o *DeleteObjectForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete object forbidden response
func (o *DeleteObjectForbidden) Code() int {
	return 403
}

func (o *DeleteObjectForbidden) Error() string {
	return fmt.Sprintf("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] deleteObjectForbidden  %+v", 403, o.Payload)
}

func (o *DeleteObjectForbidden) String() string {
	return fmt.Sprintf("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] deleteObjectForbidden  %+v", 403, o.Payload)
}

func (o *DeleteObjectForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteObjectForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeleteObjectTooManyRequests creates a DeleteObjectTooManyRequests with default headers values
func NewDeleteObjectTooManyRequests() *DeleteObjectTooManyRequests {
	return &DeleteObjectTooManyRequests{}
}

/* DeleteObjectTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeleteObjectTooManyRequests struct {

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

// IsSuccess returns true when this delete object too many requests response has a 2xx status code
func (o *DeleteObjectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete object too many requests response has a 3xx status code
func (o *DeleteObjectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete object too many requests response has a 4xx status code
func (o *DeleteObjectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete object too many requests response has a 5xx status code
func (o *DeleteObjectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete object too many requests response a status code equal to that given
func (o *DeleteObjectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete object too many requests response
func (o *DeleteObjectTooManyRequests) Code() int {
	return 429
}

func (o *DeleteObjectTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] deleteObjectTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteObjectTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /customobjects/v1/collections/{collection_name}/objects/{object_key}][%d] deleteObjectTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteObjectTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeleteObjectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
