// Code generated by go-swagger; DO NOT EDIT.

package foundry_logscale

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

// ListViewsReader is a Reader for the ListViews structure.
type ListViewsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListViewsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListViewsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListViewsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListViewsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListViewsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListViewsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewListViewsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /loggingapi/entities/views/v1] ListViews", response, response.Code())
	}
}

// NewListViewsOK creates a ListViewsOK with default headers values
func NewListViewsOK() *ListViewsOK {
	return &ListViewsOK{}
}

/*
ListViewsOK describes a response with status code 200, with default header values.

OK
*/
type ListViewsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ApidomainRepoViewListItemWrapperV1
}

// IsSuccess returns true when this list views o k response has a 2xx status code
func (o *ListViewsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list views o k response has a 3xx status code
func (o *ListViewsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list views o k response has a 4xx status code
func (o *ListViewsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list views o k response has a 5xx status code
func (o *ListViewsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list views o k response a status code equal to that given
func (o *ListViewsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list views o k response
func (o *ListViewsOK) Code() int {
	return 200
}

func (o *ListViewsOK) Error() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsOK  %+v", 200, o.Payload)
}

func (o *ListViewsOK) String() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsOK  %+v", 200, o.Payload)
}

func (o *ListViewsOK) GetPayload() *models.ApidomainRepoViewListItemWrapperV1 {
	return o.Payload
}

func (o *ListViewsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ApidomainRepoViewListItemWrapperV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListViewsBadRequest creates a ListViewsBadRequest with default headers values
func NewListViewsBadRequest() *ListViewsBadRequest {
	return &ListViewsBadRequest{}
}

/*
ListViewsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type ListViewsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this list views bad request response has a 2xx status code
func (o *ListViewsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list views bad request response has a 3xx status code
func (o *ListViewsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list views bad request response has a 4xx status code
func (o *ListViewsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list views bad request response has a 5xx status code
func (o *ListViewsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list views bad request response a status code equal to that given
func (o *ListViewsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list views bad request response
func (o *ListViewsBadRequest) Code() int {
	return 400
}

func (o *ListViewsBadRequest) Error() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsBadRequest  %+v", 400, o.Payload)
}

func (o *ListViewsBadRequest) String() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsBadRequest  %+v", 400, o.Payload)
}

func (o *ListViewsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ListViewsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListViewsForbidden creates a ListViewsForbidden with default headers values
func NewListViewsForbidden() *ListViewsForbidden {
	return &ListViewsForbidden{}
}

/*
ListViewsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListViewsForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this list views forbidden response has a 2xx status code
func (o *ListViewsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list views forbidden response has a 3xx status code
func (o *ListViewsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list views forbidden response has a 4xx status code
func (o *ListViewsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list views forbidden response has a 5xx status code
func (o *ListViewsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list views forbidden response a status code equal to that given
func (o *ListViewsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list views forbidden response
func (o *ListViewsForbidden) Code() int {
	return 403
}

func (o *ListViewsForbidden) Error() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsForbidden  %+v", 403, o.Payload)
}

func (o *ListViewsForbidden) String() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsForbidden  %+v", 403, o.Payload)
}

func (o *ListViewsForbidden) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ListViewsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListViewsNotFound creates a ListViewsNotFound with default headers values
func NewListViewsNotFound() *ListViewsNotFound {
	return &ListViewsNotFound{}
}

/*
ListViewsNotFound describes a response with status code 404, with default header values.

Not Found
*/
type ListViewsNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this list views not found response has a 2xx status code
func (o *ListViewsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list views not found response has a 3xx status code
func (o *ListViewsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list views not found response has a 4xx status code
func (o *ListViewsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list views not found response has a 5xx status code
func (o *ListViewsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list views not found response a status code equal to that given
func (o *ListViewsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list views not found response
func (o *ListViewsNotFound) Code() int {
	return 404
}

func (o *ListViewsNotFound) Error() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsNotFound  %+v", 404, o.Payload)
}

func (o *ListViewsNotFound) String() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsNotFound  %+v", 404, o.Payload)
}

func (o *ListViewsNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ListViewsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListViewsTooManyRequests creates a ListViewsTooManyRequests with default headers values
func NewListViewsTooManyRequests() *ListViewsTooManyRequests {
	return &ListViewsTooManyRequests{}
}

/*
ListViewsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ListViewsTooManyRequests struct {

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

// IsSuccess returns true when this list views too many requests response has a 2xx status code
func (o *ListViewsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list views too many requests response has a 3xx status code
func (o *ListViewsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list views too many requests response has a 4xx status code
func (o *ListViewsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list views too many requests response has a 5xx status code
func (o *ListViewsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list views too many requests response a status code equal to that given
func (o *ListViewsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list views too many requests response
func (o *ListViewsTooManyRequests) Code() int {
	return 429
}

func (o *ListViewsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListViewsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListViewsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ListViewsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewListViewsInternalServerError creates a ListViewsInternalServerError with default headers values
func NewListViewsInternalServerError() *ListViewsInternalServerError {
	return &ListViewsInternalServerError{}
}

/*
ListViewsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ListViewsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this list views internal server error response has a 2xx status code
func (o *ListViewsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list views internal server error response has a 3xx status code
func (o *ListViewsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list views internal server error response has a 4xx status code
func (o *ListViewsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this list views internal server error response has a 5xx status code
func (o *ListViewsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this list views internal server error response a status code equal to that given
func (o *ListViewsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the list views internal server error response
func (o *ListViewsInternalServerError) Code() int {
	return 500
}

func (o *ListViewsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsInternalServerError  %+v", 500, o.Payload)
}

func (o *ListViewsInternalServerError) String() string {
	return fmt.Sprintf("[GET /loggingapi/entities/views/v1][%d] listViewsInternalServerError  %+v", 500, o.Payload)
}

func (o *ListViewsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *ListViewsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
