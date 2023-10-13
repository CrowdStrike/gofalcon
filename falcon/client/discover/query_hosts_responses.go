// Code generated by go-swagger; DO NOT EDIT.

package discover

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

// QueryHostsReader is a Reader for the QueryHosts structure.
type QueryHostsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryHostsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryHostsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryHostsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryHostsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryHostsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryHostsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /discover/queries/hosts/v1] query-hosts", response, response.Code())
	}
}

// NewQueryHostsOK creates a QueryHostsOK with default headers values
func NewQueryHostsOK() *QueryHostsOK {
	return &QueryHostsOK{}
}

/* QueryHostsOK describes a response with status code 200, with default header values.

OK
*/
type QueryHostsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecQueryResponse
}

// IsSuccess returns true when this query hosts o k response has a 2xx status code
func (o *QueryHostsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query hosts o k response has a 3xx status code
func (o *QueryHostsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hosts o k response has a 4xx status code
func (o *QueryHostsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query hosts o k response has a 5xx status code
func (o *QueryHostsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query hosts o k response a status code equal to that given
func (o *QueryHostsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query hosts o k response
func (o *QueryHostsOK) Code() int {
	return 200
}

func (o *QueryHostsOK) Error() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsOK  %+v", 200, o.Payload)
}

func (o *QueryHostsOK) String() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsOK  %+v", 200, o.Payload)
}

func (o *QueryHostsOK) GetPayload() *models.MsaspecQueryResponse {
	return o.Payload
}

func (o *QueryHostsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryHostsBadRequest creates a QueryHostsBadRequest with default headers values
func NewQueryHostsBadRequest() *QueryHostsBadRequest {
	return &QueryHostsBadRequest{}
}

/* QueryHostsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryHostsBadRequest struct {

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

// IsSuccess returns true when this query hosts bad request response has a 2xx status code
func (o *QueryHostsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hosts bad request response has a 3xx status code
func (o *QueryHostsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hosts bad request response has a 4xx status code
func (o *QueryHostsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query hosts bad request response has a 5xx status code
func (o *QueryHostsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query hosts bad request response a status code equal to that given
func (o *QueryHostsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query hosts bad request response
func (o *QueryHostsBadRequest) Code() int {
	return 400
}

func (o *QueryHostsBadRequest) Error() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsBadRequest  %+v", 400, o.Payload)
}

func (o *QueryHostsBadRequest) String() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsBadRequest  %+v", 400, o.Payload)
}

func (o *QueryHostsBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryHostsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryHostsForbidden creates a QueryHostsForbidden with default headers values
func NewQueryHostsForbidden() *QueryHostsForbidden {
	return &QueryHostsForbidden{}
}

/* QueryHostsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryHostsForbidden struct {

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

// IsSuccess returns true when this query hosts forbidden response has a 2xx status code
func (o *QueryHostsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hosts forbidden response has a 3xx status code
func (o *QueryHostsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hosts forbidden response has a 4xx status code
func (o *QueryHostsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query hosts forbidden response has a 5xx status code
func (o *QueryHostsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query hosts forbidden response a status code equal to that given
func (o *QueryHostsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query hosts forbidden response
func (o *QueryHostsForbidden) Code() int {
	return 403
}

func (o *QueryHostsForbidden) Error() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsForbidden  %+v", 403, o.Payload)
}

func (o *QueryHostsForbidden) String() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsForbidden  %+v", 403, o.Payload)
}

func (o *QueryHostsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryHostsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryHostsTooManyRequests creates a QueryHostsTooManyRequests with default headers values
func NewQueryHostsTooManyRequests() *QueryHostsTooManyRequests {
	return &QueryHostsTooManyRequests{}
}

/* QueryHostsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryHostsTooManyRequests struct {

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

// IsSuccess returns true when this query hosts too many requests response has a 2xx status code
func (o *QueryHostsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hosts too many requests response has a 3xx status code
func (o *QueryHostsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hosts too many requests response has a 4xx status code
func (o *QueryHostsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query hosts too many requests response has a 5xx status code
func (o *QueryHostsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query hosts too many requests response a status code equal to that given
func (o *QueryHostsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query hosts too many requests response
func (o *QueryHostsTooManyRequests) Code() int {
	return 429
}

func (o *QueryHostsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryHostsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryHostsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryHostsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryHostsInternalServerError creates a QueryHostsInternalServerError with default headers values
func NewQueryHostsInternalServerError() *QueryHostsInternalServerError {
	return &QueryHostsInternalServerError{}
}

/* QueryHostsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryHostsInternalServerError struct {

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

// IsSuccess returns true when this query hosts internal server error response has a 2xx status code
func (o *QueryHostsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query hosts internal server error response has a 3xx status code
func (o *QueryHostsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query hosts internal server error response has a 4xx status code
func (o *QueryHostsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query hosts internal server error response has a 5xx status code
func (o *QueryHostsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query hosts internal server error response a status code equal to that given
func (o *QueryHostsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query hosts internal server error response
func (o *QueryHostsInternalServerError) Code() int {
	return 500
}

func (o *QueryHostsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryHostsInternalServerError) String() string {
	return fmt.Sprintf("[GET /discover/queries/hosts/v1][%d] queryHostsInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryHostsInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *QueryHostsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
