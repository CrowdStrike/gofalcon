// Code generated by go-swagger; DO NOT EDIT.

package falcon_complete_dashboard

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

// GetDeviceCountCollectionQueriesByFilterReader is a Reader for the GetDeviceCountCollectionQueriesByFilter structure.
type GetDeviceCountCollectionQueriesByFilterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDeviceCountCollectionQueriesByFilterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDeviceCountCollectionQueriesByFilterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetDeviceCountCollectionQueriesByFilterForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDeviceCountCollectionQueriesByFilterTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetDeviceCountCollectionQueriesByFilterInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1] GetDeviceCountCollectionQueriesByFilter", response, response.Code())
	}
}

// NewGetDeviceCountCollectionQueriesByFilterOK creates a GetDeviceCountCollectionQueriesByFilterOK with default headers values
func NewGetDeviceCountCollectionQueriesByFilterOK() *GetDeviceCountCollectionQueriesByFilterOK {
	return &GetDeviceCountCollectionQueriesByFilterOK{}
}

/*
GetDeviceCountCollectionQueriesByFilterOK describes a response with status code 200, with default header values.

OK
*/
type GetDeviceCountCollectionQueriesByFilterOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaQueryResponse
}

// IsSuccess returns true when this get device count collection queries by filter o k response has a 2xx status code
func (o *GetDeviceCountCollectionQueriesByFilterOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get device count collection queries by filter o k response has a 3xx status code
func (o *GetDeviceCountCollectionQueriesByFilterOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get device count collection queries by filter o k response has a 4xx status code
func (o *GetDeviceCountCollectionQueriesByFilterOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get device count collection queries by filter o k response has a 5xx status code
func (o *GetDeviceCountCollectionQueriesByFilterOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get device count collection queries by filter o k response a status code equal to that given
func (o *GetDeviceCountCollectionQueriesByFilterOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get device count collection queries by filter o k response
func (o *GetDeviceCountCollectionQueriesByFilterOK) Code() int {
	return 200
}

func (o *GetDeviceCountCollectionQueriesByFilterOK) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterOK  %+v", 200, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterOK) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterOK  %+v", 200, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *GetDeviceCountCollectionQueriesByFilterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDeviceCountCollectionQueriesByFilterForbidden creates a GetDeviceCountCollectionQueriesByFilterForbidden with default headers values
func NewGetDeviceCountCollectionQueriesByFilterForbidden() *GetDeviceCountCollectionQueriesByFilterForbidden {
	return &GetDeviceCountCollectionQueriesByFilterForbidden{}
}

/*
GetDeviceCountCollectionQueriesByFilterForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetDeviceCountCollectionQueriesByFilterForbidden struct {

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

// IsSuccess returns true when this get device count collection queries by filter forbidden response has a 2xx status code
func (o *GetDeviceCountCollectionQueriesByFilterForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get device count collection queries by filter forbidden response has a 3xx status code
func (o *GetDeviceCountCollectionQueriesByFilterForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get device count collection queries by filter forbidden response has a 4xx status code
func (o *GetDeviceCountCollectionQueriesByFilterForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get device count collection queries by filter forbidden response has a 5xx status code
func (o *GetDeviceCountCollectionQueriesByFilterForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get device count collection queries by filter forbidden response a status code equal to that given
func (o *GetDeviceCountCollectionQueriesByFilterForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get device count collection queries by filter forbidden response
func (o *GetDeviceCountCollectionQueriesByFilterForbidden) Code() int {
	return 403
}

func (o *GetDeviceCountCollectionQueriesByFilterForbidden) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterForbidden  %+v", 403, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterForbidden) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterForbidden  %+v", 403, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetDeviceCountCollectionQueriesByFilterForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDeviceCountCollectionQueriesByFilterTooManyRequests creates a GetDeviceCountCollectionQueriesByFilterTooManyRequests with default headers values
func NewGetDeviceCountCollectionQueriesByFilterTooManyRequests() *GetDeviceCountCollectionQueriesByFilterTooManyRequests {
	return &GetDeviceCountCollectionQueriesByFilterTooManyRequests{}
}

/*
GetDeviceCountCollectionQueriesByFilterTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetDeviceCountCollectionQueriesByFilterTooManyRequests struct {

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

// IsSuccess returns true when this get device count collection queries by filter too many requests response has a 2xx status code
func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get device count collection queries by filter too many requests response has a 3xx status code
func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get device count collection queries by filter too many requests response has a 4xx status code
func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get device count collection queries by filter too many requests response has a 5xx status code
func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get device count collection queries by filter too many requests response a status code equal to that given
func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get device count collection queries by filter too many requests response
func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) Code() int {
	return 429
}

func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetDeviceCountCollectionQueriesByFilterTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDeviceCountCollectionQueriesByFilterInternalServerError creates a GetDeviceCountCollectionQueriesByFilterInternalServerError with default headers values
func NewGetDeviceCountCollectionQueriesByFilterInternalServerError() *GetDeviceCountCollectionQueriesByFilterInternalServerError {
	return &GetDeviceCountCollectionQueriesByFilterInternalServerError{}
}

/*
GetDeviceCountCollectionQueriesByFilterInternalServerError describes a response with status code 500, with default header values.

Unexpected Error
*/
type GetDeviceCountCollectionQueriesByFilterInternalServerError struct {

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

// IsSuccess returns true when this get device count collection queries by filter internal server error response has a 2xx status code
func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get device count collection queries by filter internal server error response has a 3xx status code
func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get device count collection queries by filter internal server error response has a 4xx status code
func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get device count collection queries by filter internal server error response has a 5xx status code
func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get device count collection queries by filter internal server error response a status code equal to that given
func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get device count collection queries by filter internal server error response
func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) Code() int {
	return 500
}

func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) Error() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterInternalServerError  %+v", 500, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) String() string {
	return fmt.Sprintf("[GET /falcon-complete-dashboards/queries/devicecount-collections/v1][%d] getDeviceCountCollectionQueriesByFilterInternalServerError  %+v", 500, o.Payload)
}

func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetDeviceCountCollectionQueriesByFilterInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
