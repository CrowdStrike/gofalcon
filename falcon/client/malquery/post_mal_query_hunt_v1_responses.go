// Code generated by go-swagger; DO NOT EDIT.

package malquery

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/aslape/gofalcon/falcon/models"
)

// PostMalQueryHuntV1Reader is a Reader for the PostMalQueryHuntV1 structure.
type PostMalQueryHuntV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostMalQueryHuntV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostMalQueryHuntV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostMalQueryHuntV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostMalQueryHuntV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostMalQueryHuntV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPostMalQueryHuntV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostMalQueryHuntV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /malquery/queries/hunt/v1] PostMalQueryHuntV1", response, response.Code())
	}
}

// NewPostMalQueryHuntV1OK creates a PostMalQueryHuntV1OK with default headers values
func NewPostMalQueryHuntV1OK() *PostMalQueryHuntV1OK {
	return &PostMalQueryHuntV1OK{}
}

/*
PostMalQueryHuntV1OK describes a response with status code 200, with default header values.

OK
*/
type PostMalQueryHuntV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MalqueryExternalQueryResponse
}

// IsSuccess returns true when this post mal query hunt v1 o k response has a 2xx status code
func (o *PostMalQueryHuntV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post mal query hunt v1 o k response has a 3xx status code
func (o *PostMalQueryHuntV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post mal query hunt v1 o k response has a 4xx status code
func (o *PostMalQueryHuntV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post mal query hunt v1 o k response has a 5xx status code
func (o *PostMalQueryHuntV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this post mal query hunt v1 o k response a status code equal to that given
func (o *PostMalQueryHuntV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post mal query hunt v1 o k response
func (o *PostMalQueryHuntV1OK) Code() int {
	return 200
}

func (o *PostMalQueryHuntV1OK) Error() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1OK  %+v", 200, o.Payload)
}

func (o *PostMalQueryHuntV1OK) String() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1OK  %+v", 200, o.Payload)
}

func (o *PostMalQueryHuntV1OK) GetPayload() *models.MalqueryExternalQueryResponse {
	return o.Payload
}

func (o *PostMalQueryHuntV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MalqueryExternalQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMalQueryHuntV1BadRequest creates a PostMalQueryHuntV1BadRequest with default headers values
func NewPostMalQueryHuntV1BadRequest() *PostMalQueryHuntV1BadRequest {
	return &PostMalQueryHuntV1BadRequest{}
}

/*
PostMalQueryHuntV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostMalQueryHuntV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MalqueryExternalQueryResponse
}

// IsSuccess returns true when this post mal query hunt v1 bad request response has a 2xx status code
func (o *PostMalQueryHuntV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post mal query hunt v1 bad request response has a 3xx status code
func (o *PostMalQueryHuntV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post mal query hunt v1 bad request response has a 4xx status code
func (o *PostMalQueryHuntV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post mal query hunt v1 bad request response has a 5xx status code
func (o *PostMalQueryHuntV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post mal query hunt v1 bad request response a status code equal to that given
func (o *PostMalQueryHuntV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post mal query hunt v1 bad request response
func (o *PostMalQueryHuntV1BadRequest) Code() int {
	return 400
}

func (o *PostMalQueryHuntV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1BadRequest  %+v", 400, o.Payload)
}

func (o *PostMalQueryHuntV1BadRequest) String() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1BadRequest  %+v", 400, o.Payload)
}

func (o *PostMalQueryHuntV1BadRequest) GetPayload() *models.MalqueryExternalQueryResponse {
	return o.Payload
}

func (o *PostMalQueryHuntV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MalqueryExternalQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMalQueryHuntV1Unauthorized creates a PostMalQueryHuntV1Unauthorized with default headers values
func NewPostMalQueryHuntV1Unauthorized() *PostMalQueryHuntV1Unauthorized {
	return &PostMalQueryHuntV1Unauthorized{}
}

/*
PostMalQueryHuntV1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostMalQueryHuntV1Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this post mal query hunt v1 unauthorized response has a 2xx status code
func (o *PostMalQueryHuntV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post mal query hunt v1 unauthorized response has a 3xx status code
func (o *PostMalQueryHuntV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post mal query hunt v1 unauthorized response has a 4xx status code
func (o *PostMalQueryHuntV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post mal query hunt v1 unauthorized response has a 5xx status code
func (o *PostMalQueryHuntV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post mal query hunt v1 unauthorized response a status code equal to that given
func (o *PostMalQueryHuntV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post mal query hunt v1 unauthorized response
func (o *PostMalQueryHuntV1Unauthorized) Code() int {
	return 401
}

func (o *PostMalQueryHuntV1Unauthorized) Error() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1Unauthorized  %+v", 401, o.Payload)
}

func (o *PostMalQueryHuntV1Unauthorized) String() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1Unauthorized  %+v", 401, o.Payload)
}

func (o *PostMalQueryHuntV1Unauthorized) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *PostMalQueryHuntV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMalQueryHuntV1Forbidden creates a PostMalQueryHuntV1Forbidden with default headers values
func NewPostMalQueryHuntV1Forbidden() *PostMalQueryHuntV1Forbidden {
	return &PostMalQueryHuntV1Forbidden{}
}

/*
PostMalQueryHuntV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PostMalQueryHuntV1Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this post mal query hunt v1 forbidden response has a 2xx status code
func (o *PostMalQueryHuntV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post mal query hunt v1 forbidden response has a 3xx status code
func (o *PostMalQueryHuntV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post mal query hunt v1 forbidden response has a 4xx status code
func (o *PostMalQueryHuntV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this post mal query hunt v1 forbidden response has a 5xx status code
func (o *PostMalQueryHuntV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this post mal query hunt v1 forbidden response a status code equal to that given
func (o *PostMalQueryHuntV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the post mal query hunt v1 forbidden response
func (o *PostMalQueryHuntV1Forbidden) Code() int {
	return 403
}

func (o *PostMalQueryHuntV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1Forbidden  %+v", 403, o.Payload)
}

func (o *PostMalQueryHuntV1Forbidden) String() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1Forbidden  %+v", 403, o.Payload)
}

func (o *PostMalQueryHuntV1Forbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *PostMalQueryHuntV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMalQueryHuntV1TooManyRequests creates a PostMalQueryHuntV1TooManyRequests with default headers values
func NewPostMalQueryHuntV1TooManyRequests() *PostMalQueryHuntV1TooManyRequests {
	return &PostMalQueryHuntV1TooManyRequests{}
}

/*
PostMalQueryHuntV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type PostMalQueryHuntV1TooManyRequests struct {

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

	Payload *models.MalqueryExternalQueryResponse
}

// IsSuccess returns true when this post mal query hunt v1 too many requests response has a 2xx status code
func (o *PostMalQueryHuntV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post mal query hunt v1 too many requests response has a 3xx status code
func (o *PostMalQueryHuntV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post mal query hunt v1 too many requests response has a 4xx status code
func (o *PostMalQueryHuntV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this post mal query hunt v1 too many requests response has a 5xx status code
func (o *PostMalQueryHuntV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this post mal query hunt v1 too many requests response a status code equal to that given
func (o *PostMalQueryHuntV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the post mal query hunt v1 too many requests response
func (o *PostMalQueryHuntV1TooManyRequests) Code() int {
	return 429
}

func (o *PostMalQueryHuntV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *PostMalQueryHuntV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *PostMalQueryHuntV1TooManyRequests) GetPayload() *models.MalqueryExternalQueryResponse {
	return o.Payload
}

func (o *PostMalQueryHuntV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MalqueryExternalQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostMalQueryHuntV1InternalServerError creates a PostMalQueryHuntV1InternalServerError with default headers values
func NewPostMalQueryHuntV1InternalServerError() *PostMalQueryHuntV1InternalServerError {
	return &PostMalQueryHuntV1InternalServerError{}
}

/*
PostMalQueryHuntV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostMalQueryHuntV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MalqueryExternalQueryResponse
}

// IsSuccess returns true when this post mal query hunt v1 internal server error response has a 2xx status code
func (o *PostMalQueryHuntV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post mal query hunt v1 internal server error response has a 3xx status code
func (o *PostMalQueryHuntV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post mal query hunt v1 internal server error response has a 4xx status code
func (o *PostMalQueryHuntV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post mal query hunt v1 internal server error response has a 5xx status code
func (o *PostMalQueryHuntV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post mal query hunt v1 internal server error response a status code equal to that given
func (o *PostMalQueryHuntV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post mal query hunt v1 internal server error response
func (o *PostMalQueryHuntV1InternalServerError) Code() int {
	return 500
}

func (o *PostMalQueryHuntV1InternalServerError) Error() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1InternalServerError  %+v", 500, o.Payload)
}

func (o *PostMalQueryHuntV1InternalServerError) String() string {
	return fmt.Sprintf("[POST /malquery/queries/hunt/v1][%d] postMalQueryHuntV1InternalServerError  %+v", 500, o.Payload)
}

func (o *PostMalQueryHuntV1InternalServerError) GetPayload() *models.MalqueryExternalQueryResponse {
	return o.Payload
}

func (o *PostMalQueryHuntV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MalqueryExternalQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
