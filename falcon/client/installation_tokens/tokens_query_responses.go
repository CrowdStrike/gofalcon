// Code generated by go-swagger; DO NOT EDIT.

package installation_tokens

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

// TokensQueryReader is a Reader for the TokensQuery structure.
type TokensQueryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TokensQueryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTokensQueryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewTokensQueryBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewTokensQueryForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewTokensQueryTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewTokensQueryInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /installation-tokens/queries/tokens/v1] tokens-query", response, response.Code())
	}
}

// NewTokensQueryOK creates a TokensQueryOK with default headers values
func NewTokensQueryOK() *TokensQueryOK {
	return &TokensQueryOK{}
}

/* TokensQueryOK describes a response with status code 200, with default header values.

OK
*/
type TokensQueryOK struct {

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

// IsSuccess returns true when this tokens query o k response has a 2xx status code
func (o *TokensQueryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this tokens query o k response has a 3xx status code
func (o *TokensQueryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this tokens query o k response has a 4xx status code
func (o *TokensQueryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this tokens query o k response has a 5xx status code
func (o *TokensQueryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this tokens query o k response a status code equal to that given
func (o *TokensQueryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the tokens query o k response
func (o *TokensQueryOK) Code() int {
	return 200
}

func (o *TokensQueryOK) Error() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryOK  %+v", 200, o.Payload)
}

func (o *TokensQueryOK) String() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryOK  %+v", 200, o.Payload)
}

func (o *TokensQueryOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *TokensQueryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewTokensQueryBadRequest creates a TokensQueryBadRequest with default headers values
func NewTokensQueryBadRequest() *TokensQueryBadRequest {
	return &TokensQueryBadRequest{}
}

/* TokensQueryBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type TokensQueryBadRequest struct {

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

// IsSuccess returns true when this tokens query bad request response has a 2xx status code
func (o *TokensQueryBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this tokens query bad request response has a 3xx status code
func (o *TokensQueryBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this tokens query bad request response has a 4xx status code
func (o *TokensQueryBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this tokens query bad request response has a 5xx status code
func (o *TokensQueryBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this tokens query bad request response a status code equal to that given
func (o *TokensQueryBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the tokens query bad request response
func (o *TokensQueryBadRequest) Code() int {
	return 400
}

func (o *TokensQueryBadRequest) Error() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryBadRequest  %+v", 400, o.Payload)
}

func (o *TokensQueryBadRequest) String() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryBadRequest  %+v", 400, o.Payload)
}

func (o *TokensQueryBadRequest) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *TokensQueryBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewTokensQueryForbidden creates a TokensQueryForbidden with default headers values
func NewTokensQueryForbidden() *TokensQueryForbidden {
	return &TokensQueryForbidden{}
}

/* TokensQueryForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type TokensQueryForbidden struct {

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

// IsSuccess returns true when this tokens query forbidden response has a 2xx status code
func (o *TokensQueryForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this tokens query forbidden response has a 3xx status code
func (o *TokensQueryForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this tokens query forbidden response has a 4xx status code
func (o *TokensQueryForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this tokens query forbidden response has a 5xx status code
func (o *TokensQueryForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this tokens query forbidden response a status code equal to that given
func (o *TokensQueryForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the tokens query forbidden response
func (o *TokensQueryForbidden) Code() int {
	return 403
}

func (o *TokensQueryForbidden) Error() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryForbidden  %+v", 403, o.Payload)
}

func (o *TokensQueryForbidden) String() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryForbidden  %+v", 403, o.Payload)
}

func (o *TokensQueryForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *TokensQueryForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewTokensQueryTooManyRequests creates a TokensQueryTooManyRequests with default headers values
func NewTokensQueryTooManyRequests() *TokensQueryTooManyRequests {
	return &TokensQueryTooManyRequests{}
}

/* TokensQueryTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type TokensQueryTooManyRequests struct {

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

// IsSuccess returns true when this tokens query too many requests response has a 2xx status code
func (o *TokensQueryTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this tokens query too many requests response has a 3xx status code
func (o *TokensQueryTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this tokens query too many requests response has a 4xx status code
func (o *TokensQueryTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this tokens query too many requests response has a 5xx status code
func (o *TokensQueryTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this tokens query too many requests response a status code equal to that given
func (o *TokensQueryTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the tokens query too many requests response
func (o *TokensQueryTooManyRequests) Code() int {
	return 429
}

func (o *TokensQueryTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryTooManyRequests  %+v", 429, o.Payload)
}

func (o *TokensQueryTooManyRequests) String() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryTooManyRequests  %+v", 429, o.Payload)
}

func (o *TokensQueryTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *TokensQueryTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewTokensQueryInternalServerError creates a TokensQueryInternalServerError with default headers values
func NewTokensQueryInternalServerError() *TokensQueryInternalServerError {
	return &TokensQueryInternalServerError{}
}

/* TokensQueryInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type TokensQueryInternalServerError struct {

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

// IsSuccess returns true when this tokens query internal server error response has a 2xx status code
func (o *TokensQueryInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this tokens query internal server error response has a 3xx status code
func (o *TokensQueryInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this tokens query internal server error response has a 4xx status code
func (o *TokensQueryInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this tokens query internal server error response has a 5xx status code
func (o *TokensQueryInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this tokens query internal server error response a status code equal to that given
func (o *TokensQueryInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the tokens query internal server error response
func (o *TokensQueryInternalServerError) Code() int {
	return 500
}

func (o *TokensQueryInternalServerError) Error() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryInternalServerError  %+v", 500, o.Payload)
}

func (o *TokensQueryInternalServerError) String() string {
	return fmt.Sprintf("[GET /installation-tokens/queries/tokens/v1][%d] tokensQueryInternalServerError  %+v", 500, o.Payload)
}

func (o *TokensQueryInternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *TokensQueryInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
