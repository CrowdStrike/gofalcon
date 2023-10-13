// Code generated by go-swagger; DO NOT EDIT.

package incidents

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

// QueryBehaviorsReader is a Reader for the QueryBehaviors structure.
type QueryBehaviorsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryBehaviorsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryBehaviorsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryBehaviorsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewQueryBehaviorsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewQueryBehaviorsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryBehaviorsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /incidents/queries/behaviors/v1] QueryBehaviors", response, response.Code())
	}
}

// NewQueryBehaviorsOK creates a QueryBehaviorsOK with default headers values
func NewQueryBehaviorsOK() *QueryBehaviorsOK {
	return &QueryBehaviorsOK{}
}

/* QueryBehaviorsOK describes a response with status code 200, with default header values.

OK
*/
type QueryBehaviorsOK struct {

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

// IsSuccess returns true when this query behaviors o k response has a 2xx status code
func (o *QueryBehaviorsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query behaviors o k response has a 3xx status code
func (o *QueryBehaviorsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query behaviors o k response has a 4xx status code
func (o *QueryBehaviorsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query behaviors o k response has a 5xx status code
func (o *QueryBehaviorsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query behaviors o k response a status code equal to that given
func (o *QueryBehaviorsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query behaviors o k response
func (o *QueryBehaviorsOK) Code() int {
	return 200
}

func (o *QueryBehaviorsOK) Error() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsOK  %+v", 200, o.Payload)
}

func (o *QueryBehaviorsOK) String() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsOK  %+v", 200, o.Payload)
}

func (o *QueryBehaviorsOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *QueryBehaviorsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryBehaviorsBadRequest creates a QueryBehaviorsBadRequest with default headers values
func NewQueryBehaviorsBadRequest() *QueryBehaviorsBadRequest {
	return &QueryBehaviorsBadRequest{}
}

/* QueryBehaviorsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type QueryBehaviorsBadRequest struct {

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

// IsSuccess returns true when this query behaviors bad request response has a 2xx status code
func (o *QueryBehaviorsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query behaviors bad request response has a 3xx status code
func (o *QueryBehaviorsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query behaviors bad request response has a 4xx status code
func (o *QueryBehaviorsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query behaviors bad request response has a 5xx status code
func (o *QueryBehaviorsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query behaviors bad request response a status code equal to that given
func (o *QueryBehaviorsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query behaviors bad request response
func (o *QueryBehaviorsBadRequest) Code() int {
	return 400
}

func (o *QueryBehaviorsBadRequest) Error() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsBadRequest  %+v", 400, o.Payload)
}

func (o *QueryBehaviorsBadRequest) String() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsBadRequest  %+v", 400, o.Payload)
}

func (o *QueryBehaviorsBadRequest) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryBehaviorsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryBehaviorsForbidden creates a QueryBehaviorsForbidden with default headers values
func NewQueryBehaviorsForbidden() *QueryBehaviorsForbidden {
	return &QueryBehaviorsForbidden{}
}

/* QueryBehaviorsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type QueryBehaviorsForbidden struct {

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

// IsSuccess returns true when this query behaviors forbidden response has a 2xx status code
func (o *QueryBehaviorsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query behaviors forbidden response has a 3xx status code
func (o *QueryBehaviorsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query behaviors forbidden response has a 4xx status code
func (o *QueryBehaviorsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this query behaviors forbidden response has a 5xx status code
func (o *QueryBehaviorsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this query behaviors forbidden response a status code equal to that given
func (o *QueryBehaviorsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the query behaviors forbidden response
func (o *QueryBehaviorsForbidden) Code() int {
	return 403
}

func (o *QueryBehaviorsForbidden) Error() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsForbidden  %+v", 403, o.Payload)
}

func (o *QueryBehaviorsForbidden) String() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsForbidden  %+v", 403, o.Payload)
}

func (o *QueryBehaviorsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryBehaviorsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryBehaviorsTooManyRequests creates a QueryBehaviorsTooManyRequests with default headers values
func NewQueryBehaviorsTooManyRequests() *QueryBehaviorsTooManyRequests {
	return &QueryBehaviorsTooManyRequests{}
}

/* QueryBehaviorsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type QueryBehaviorsTooManyRequests struct {

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

// IsSuccess returns true when this query behaviors too many requests response has a 2xx status code
func (o *QueryBehaviorsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query behaviors too many requests response has a 3xx status code
func (o *QueryBehaviorsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query behaviors too many requests response has a 4xx status code
func (o *QueryBehaviorsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this query behaviors too many requests response has a 5xx status code
func (o *QueryBehaviorsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this query behaviors too many requests response a status code equal to that given
func (o *QueryBehaviorsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the query behaviors too many requests response
func (o *QueryBehaviorsTooManyRequests) Code() int {
	return 429
}

func (o *QueryBehaviorsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryBehaviorsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsTooManyRequests  %+v", 429, o.Payload)
}

func (o *QueryBehaviorsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryBehaviorsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewQueryBehaviorsInternalServerError creates a QueryBehaviorsInternalServerError with default headers values
func NewQueryBehaviorsInternalServerError() *QueryBehaviorsInternalServerError {
	return &QueryBehaviorsInternalServerError{}
}

/* QueryBehaviorsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type QueryBehaviorsInternalServerError struct {

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

// IsSuccess returns true when this query behaviors internal server error response has a 2xx status code
func (o *QueryBehaviorsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query behaviors internal server error response has a 3xx status code
func (o *QueryBehaviorsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query behaviors internal server error response has a 4xx status code
func (o *QueryBehaviorsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query behaviors internal server error response has a 5xx status code
func (o *QueryBehaviorsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query behaviors internal server error response a status code equal to that given
func (o *QueryBehaviorsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query behaviors internal server error response
func (o *QueryBehaviorsInternalServerError) Code() int {
	return 500
}

func (o *QueryBehaviorsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryBehaviorsInternalServerError) String() string {
	return fmt.Sprintf("[GET /incidents/queries/behaviors/v1][%d] queryBehaviorsInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryBehaviorsInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *QueryBehaviorsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
