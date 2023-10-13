// Code generated by go-swagger; DO NOT EDIT.

package ml_exclusions

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

// CreateMLExclusionsV1Reader is a Reader for the CreateMLExclusionsV1 structure.
type CreateMLExclusionsV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateMLExclusionsV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateMLExclusionsV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateMLExclusionsV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateMLExclusionsV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateMLExclusionsV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateMLExclusionsV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /policy/entities/ml-exclusions/v1] createMLExclusionsV1", response, response.Code())
	}
}

// NewCreateMLExclusionsV1OK creates a CreateMLExclusionsV1OK with default headers values
func NewCreateMLExclusionsV1OK() *CreateMLExclusionsV1OK {
	return &CreateMLExclusionsV1OK{}
}

/* CreateMLExclusionsV1OK describes a response with status code 200, with default header values.

OK
*/
type CreateMLExclusionsV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ExclusionsRespV1
}

// IsSuccess returns true when this create m l exclusions v1 o k response has a 2xx status code
func (o *CreateMLExclusionsV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create m l exclusions v1 o k response has a 3xx status code
func (o *CreateMLExclusionsV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create m l exclusions v1 o k response has a 4xx status code
func (o *CreateMLExclusionsV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create m l exclusions v1 o k response has a 5xx status code
func (o *CreateMLExclusionsV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this create m l exclusions v1 o k response a status code equal to that given
func (o *CreateMLExclusionsV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create m l exclusions v1 o k response
func (o *CreateMLExclusionsV1OK) Code() int {
	return 200
}

func (o *CreateMLExclusionsV1OK) Error() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1OK  %+v", 200, o.Payload)
}

func (o *CreateMLExclusionsV1OK) String() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1OK  %+v", 200, o.Payload)
}

func (o *CreateMLExclusionsV1OK) GetPayload() *models.ExclusionsRespV1 {
	return o.Payload
}

func (o *CreateMLExclusionsV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ExclusionsRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMLExclusionsV1BadRequest creates a CreateMLExclusionsV1BadRequest with default headers values
func NewCreateMLExclusionsV1BadRequest() *CreateMLExclusionsV1BadRequest {
	return &CreateMLExclusionsV1BadRequest{}
}

/* CreateMLExclusionsV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateMLExclusionsV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ExclusionsRespV1
}

// IsSuccess returns true when this create m l exclusions v1 bad request response has a 2xx status code
func (o *CreateMLExclusionsV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create m l exclusions v1 bad request response has a 3xx status code
func (o *CreateMLExclusionsV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create m l exclusions v1 bad request response has a 4xx status code
func (o *CreateMLExclusionsV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create m l exclusions v1 bad request response has a 5xx status code
func (o *CreateMLExclusionsV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create m l exclusions v1 bad request response a status code equal to that given
func (o *CreateMLExclusionsV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create m l exclusions v1 bad request response
func (o *CreateMLExclusionsV1BadRequest) Code() int {
	return 400
}

func (o *CreateMLExclusionsV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1BadRequest  %+v", 400, o.Payload)
}

func (o *CreateMLExclusionsV1BadRequest) String() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1BadRequest  %+v", 400, o.Payload)
}

func (o *CreateMLExclusionsV1BadRequest) GetPayload() *models.ExclusionsRespV1 {
	return o.Payload
}

func (o *CreateMLExclusionsV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ExclusionsRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMLExclusionsV1Forbidden creates a CreateMLExclusionsV1Forbidden with default headers values
func NewCreateMLExclusionsV1Forbidden() *CreateMLExclusionsV1Forbidden {
	return &CreateMLExclusionsV1Forbidden{}
}

/* CreateMLExclusionsV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateMLExclusionsV1Forbidden struct {

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

// IsSuccess returns true when this create m l exclusions v1 forbidden response has a 2xx status code
func (o *CreateMLExclusionsV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create m l exclusions v1 forbidden response has a 3xx status code
func (o *CreateMLExclusionsV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create m l exclusions v1 forbidden response has a 4xx status code
func (o *CreateMLExclusionsV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create m l exclusions v1 forbidden response has a 5xx status code
func (o *CreateMLExclusionsV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create m l exclusions v1 forbidden response a status code equal to that given
func (o *CreateMLExclusionsV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create m l exclusions v1 forbidden response
func (o *CreateMLExclusionsV1Forbidden) Code() int {
	return 403
}

func (o *CreateMLExclusionsV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1Forbidden  %+v", 403, o.Payload)
}

func (o *CreateMLExclusionsV1Forbidden) String() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1Forbidden  %+v", 403, o.Payload)
}

func (o *CreateMLExclusionsV1Forbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *CreateMLExclusionsV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateMLExclusionsV1TooManyRequests creates a CreateMLExclusionsV1TooManyRequests with default headers values
func NewCreateMLExclusionsV1TooManyRequests() *CreateMLExclusionsV1TooManyRequests {
	return &CreateMLExclusionsV1TooManyRequests{}
}

/* CreateMLExclusionsV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateMLExclusionsV1TooManyRequests struct {

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

// IsSuccess returns true when this create m l exclusions v1 too many requests response has a 2xx status code
func (o *CreateMLExclusionsV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create m l exclusions v1 too many requests response has a 3xx status code
func (o *CreateMLExclusionsV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create m l exclusions v1 too many requests response has a 4xx status code
func (o *CreateMLExclusionsV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create m l exclusions v1 too many requests response has a 5xx status code
func (o *CreateMLExclusionsV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create m l exclusions v1 too many requests response a status code equal to that given
func (o *CreateMLExclusionsV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create m l exclusions v1 too many requests response
func (o *CreateMLExclusionsV1TooManyRequests) Code() int {
	return 429
}

func (o *CreateMLExclusionsV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateMLExclusionsV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateMLExclusionsV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateMLExclusionsV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateMLExclusionsV1InternalServerError creates a CreateMLExclusionsV1InternalServerError with default headers values
func NewCreateMLExclusionsV1InternalServerError() *CreateMLExclusionsV1InternalServerError {
	return &CreateMLExclusionsV1InternalServerError{}
}

/* CreateMLExclusionsV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateMLExclusionsV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ExclusionsRespV1
}

// IsSuccess returns true when this create m l exclusions v1 internal server error response has a 2xx status code
func (o *CreateMLExclusionsV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create m l exclusions v1 internal server error response has a 3xx status code
func (o *CreateMLExclusionsV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create m l exclusions v1 internal server error response has a 4xx status code
func (o *CreateMLExclusionsV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create m l exclusions v1 internal server error response has a 5xx status code
func (o *CreateMLExclusionsV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create m l exclusions v1 internal server error response a status code equal to that given
func (o *CreateMLExclusionsV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create m l exclusions v1 internal server error response
func (o *CreateMLExclusionsV1InternalServerError) Code() int {
	return 500
}

func (o *CreateMLExclusionsV1InternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1InternalServerError  %+v", 500, o.Payload)
}

func (o *CreateMLExclusionsV1InternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/entities/ml-exclusions/v1][%d] createMLExclusionsV1InternalServerError  %+v", 500, o.Payload)
}

func (o *CreateMLExclusionsV1InternalServerError) GetPayload() *models.ExclusionsRespV1 {
	return o.Payload
}

func (o *CreateMLExclusionsV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ExclusionsRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
