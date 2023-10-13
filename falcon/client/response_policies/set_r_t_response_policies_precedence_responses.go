// Code generated by go-swagger; DO NOT EDIT.

package response_policies

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

// SetRTResponsePoliciesPrecedenceReader is a Reader for the SetRTResponsePoliciesPrecedence structure.
type SetRTResponsePoliciesPrecedenceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetRTResponsePoliciesPrecedenceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSetRTResponsePoliciesPrecedenceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetRTResponsePoliciesPrecedenceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetRTResponsePoliciesPrecedenceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetRTResponsePoliciesPrecedenceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSetRTResponsePoliciesPrecedenceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /policy/entities/response-precedence/v1] setRTResponsePoliciesPrecedence", response, response.Code())
	}
}

// NewSetRTResponsePoliciesPrecedenceOK creates a SetRTResponsePoliciesPrecedenceOK with default headers values
func NewSetRTResponsePoliciesPrecedenceOK() *SetRTResponsePoliciesPrecedenceOK {
	return &SetRTResponsePoliciesPrecedenceOK{}
}

/* SetRTResponsePoliciesPrecedenceOK describes a response with status code 200, with default header values.

OK
*/
type SetRTResponsePoliciesPrecedenceOK struct {

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

// IsSuccess returns true when this set r t response policies precedence o k response has a 2xx status code
func (o *SetRTResponsePoliciesPrecedenceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set r t response policies precedence o k response has a 3xx status code
func (o *SetRTResponsePoliciesPrecedenceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set r t response policies precedence o k response has a 4xx status code
func (o *SetRTResponsePoliciesPrecedenceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this set r t response policies precedence o k response has a 5xx status code
func (o *SetRTResponsePoliciesPrecedenceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this set r t response policies precedence o k response a status code equal to that given
func (o *SetRTResponsePoliciesPrecedenceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the set r t response policies precedence o k response
func (o *SetRTResponsePoliciesPrecedenceOK) Code() int {
	return 200
}

func (o *SetRTResponsePoliciesPrecedenceOK) Error() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceOK  %+v", 200, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceOK) String() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceOK  %+v", 200, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceOK) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *SetRTResponsePoliciesPrecedenceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSetRTResponsePoliciesPrecedenceBadRequest creates a SetRTResponsePoliciesPrecedenceBadRequest with default headers values
func NewSetRTResponsePoliciesPrecedenceBadRequest() *SetRTResponsePoliciesPrecedenceBadRequest {
	return &SetRTResponsePoliciesPrecedenceBadRequest{}
}

/* SetRTResponsePoliciesPrecedenceBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type SetRTResponsePoliciesPrecedenceBadRequest struct {

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

// IsSuccess returns true when this set r t response policies precedence bad request response has a 2xx status code
func (o *SetRTResponsePoliciesPrecedenceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set r t response policies precedence bad request response has a 3xx status code
func (o *SetRTResponsePoliciesPrecedenceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set r t response policies precedence bad request response has a 4xx status code
func (o *SetRTResponsePoliciesPrecedenceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this set r t response policies precedence bad request response has a 5xx status code
func (o *SetRTResponsePoliciesPrecedenceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this set r t response policies precedence bad request response a status code equal to that given
func (o *SetRTResponsePoliciesPrecedenceBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the set r t response policies precedence bad request response
func (o *SetRTResponsePoliciesPrecedenceBadRequest) Code() int {
	return 400
}

func (o *SetRTResponsePoliciesPrecedenceBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceBadRequest  %+v", 400, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceBadRequest) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *SetRTResponsePoliciesPrecedenceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSetRTResponsePoliciesPrecedenceForbidden creates a SetRTResponsePoliciesPrecedenceForbidden with default headers values
func NewSetRTResponsePoliciesPrecedenceForbidden() *SetRTResponsePoliciesPrecedenceForbidden {
	return &SetRTResponsePoliciesPrecedenceForbidden{}
}

/* SetRTResponsePoliciesPrecedenceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetRTResponsePoliciesPrecedenceForbidden struct {

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

// IsSuccess returns true when this set r t response policies precedence forbidden response has a 2xx status code
func (o *SetRTResponsePoliciesPrecedenceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set r t response policies precedence forbidden response has a 3xx status code
func (o *SetRTResponsePoliciesPrecedenceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set r t response policies precedence forbidden response has a 4xx status code
func (o *SetRTResponsePoliciesPrecedenceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set r t response policies precedence forbidden response has a 5xx status code
func (o *SetRTResponsePoliciesPrecedenceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set r t response policies precedence forbidden response a status code equal to that given
func (o *SetRTResponsePoliciesPrecedenceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set r t response policies precedence forbidden response
func (o *SetRTResponsePoliciesPrecedenceForbidden) Code() int {
	return 403
}

func (o *SetRTResponsePoliciesPrecedenceForbidden) Error() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceForbidden) String() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceForbidden  %+v", 403, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceForbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *SetRTResponsePoliciesPrecedenceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSetRTResponsePoliciesPrecedenceTooManyRequests creates a SetRTResponsePoliciesPrecedenceTooManyRequests with default headers values
func NewSetRTResponsePoliciesPrecedenceTooManyRequests() *SetRTResponsePoliciesPrecedenceTooManyRequests {
	return &SetRTResponsePoliciesPrecedenceTooManyRequests{}
}

/* SetRTResponsePoliciesPrecedenceTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type SetRTResponsePoliciesPrecedenceTooManyRequests struct {

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

// IsSuccess returns true when this set r t response policies precedence too many requests response has a 2xx status code
func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set r t response policies precedence too many requests response has a 3xx status code
func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set r t response policies precedence too many requests response has a 4xx status code
func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set r t response policies precedence too many requests response has a 5xx status code
func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set r t response policies precedence too many requests response a status code equal to that given
func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set r t response policies precedence too many requests response
func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) Code() int {
	return 429
}

func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) String() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *SetRTResponsePoliciesPrecedenceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSetRTResponsePoliciesPrecedenceInternalServerError creates a SetRTResponsePoliciesPrecedenceInternalServerError with default headers values
func NewSetRTResponsePoliciesPrecedenceInternalServerError() *SetRTResponsePoliciesPrecedenceInternalServerError {
	return &SetRTResponsePoliciesPrecedenceInternalServerError{}
}

/* SetRTResponsePoliciesPrecedenceInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type SetRTResponsePoliciesPrecedenceInternalServerError struct {

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

// IsSuccess returns true when this set r t response policies precedence internal server error response has a 2xx status code
func (o *SetRTResponsePoliciesPrecedenceInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set r t response policies precedence internal server error response has a 3xx status code
func (o *SetRTResponsePoliciesPrecedenceInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set r t response policies precedence internal server error response has a 4xx status code
func (o *SetRTResponsePoliciesPrecedenceInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this set r t response policies precedence internal server error response has a 5xx status code
func (o *SetRTResponsePoliciesPrecedenceInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this set r t response policies precedence internal server error response a status code equal to that given
func (o *SetRTResponsePoliciesPrecedenceInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the set r t response policies precedence internal server error response
func (o *SetRTResponsePoliciesPrecedenceInternalServerError) Code() int {
	return 500
}

func (o *SetRTResponsePoliciesPrecedenceInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/entities/response-precedence/v1][%d] setRTResponsePoliciesPrecedenceInternalServerError  %+v", 500, o.Payload)
}

func (o *SetRTResponsePoliciesPrecedenceInternalServerError) GetPayload() *models.MsaQueryResponse {
	return o.Payload
}

func (o *SetRTResponsePoliciesPrecedenceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
