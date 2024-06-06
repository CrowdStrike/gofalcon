// Code generated by go-swagger; DO NOT EDIT.

package image_assessment_policies

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

// CreatePoliciesReader is a Reader for the CreatePolicies structure.
type CreatePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreatePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreatePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewCreatePoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreatePoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreatePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /container-security/entities/image-assessment-policies/v1] CreatePolicies", response, response.Code())
	}
}

// NewCreatePoliciesOK creates a CreatePoliciesOK with default headers values
func NewCreatePoliciesOK() *CreatePoliciesOK {
	return &CreatePoliciesOK{}
}

/*
CreatePoliciesOK describes a response with status code 200, with default header values.

OK
*/
type CreatePoliciesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ModelsPolicyEntityResponse
}

// IsSuccess returns true when this create policies o k response has a 2xx status code
func (o *CreatePoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create policies o k response has a 3xx status code
func (o *CreatePoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create policies o k response has a 4xx status code
func (o *CreatePoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create policies o k response has a 5xx status code
func (o *CreatePoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create policies o k response a status code equal to that given
func (o *CreatePoliciesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create policies o k response
func (o *CreatePoliciesOK) Code() int {
	return 200
}

func (o *CreatePoliciesOK) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesOK  %+v", 200, o.Payload)
}

func (o *CreatePoliciesOK) String() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesOK  %+v", 200, o.Payload)
}

func (o *CreatePoliciesOK) GetPayload() *models.ModelsPolicyEntityResponse {
	return o.Payload
}

func (o *CreatePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ModelsPolicyEntityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoliciesForbidden creates a CreatePoliciesForbidden with default headers values
func NewCreatePoliciesForbidden() *CreatePoliciesForbidden {
	return &CreatePoliciesForbidden{}
}

/*
CreatePoliciesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreatePoliciesForbidden struct {

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

// IsSuccess returns true when this create policies forbidden response has a 2xx status code
func (o *CreatePoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create policies forbidden response has a 3xx status code
func (o *CreatePoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create policies forbidden response has a 4xx status code
func (o *CreatePoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create policies forbidden response has a 5xx status code
func (o *CreatePoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create policies forbidden response a status code equal to that given
func (o *CreatePoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create policies forbidden response
func (o *CreatePoliciesForbidden) Code() int {
	return 403
}

func (o *CreatePoliciesForbidden) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *CreatePoliciesForbidden) String() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *CreatePoliciesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreatePoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreatePoliciesTooManyRequests creates a CreatePoliciesTooManyRequests with default headers values
func NewCreatePoliciesTooManyRequests() *CreatePoliciesTooManyRequests {
	return &CreatePoliciesTooManyRequests{}
}

/*
CreatePoliciesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreatePoliciesTooManyRequests struct {

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

// IsSuccess returns true when this create policies too many requests response has a 2xx status code
func (o *CreatePoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create policies too many requests response has a 3xx status code
func (o *CreatePoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create policies too many requests response has a 4xx status code
func (o *CreatePoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create policies too many requests response has a 5xx status code
func (o *CreatePoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create policies too many requests response a status code equal to that given
func (o *CreatePoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create policies too many requests response
func (o *CreatePoliciesTooManyRequests) Code() int {
	return 429
}

func (o *CreatePoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreatePoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreatePoliciesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreatePoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreatePoliciesInternalServerError creates a CreatePoliciesInternalServerError with default headers values
func NewCreatePoliciesInternalServerError() *CreatePoliciesInternalServerError {
	return &CreatePoliciesInternalServerError{}
}

/*
CreatePoliciesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreatePoliciesInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CoreEntitiesResponse
}

// IsSuccess returns true when this create policies internal server error response has a 2xx status code
func (o *CreatePoliciesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create policies internal server error response has a 3xx status code
func (o *CreatePoliciesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create policies internal server error response has a 4xx status code
func (o *CreatePoliciesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create policies internal server error response has a 5xx status code
func (o *CreatePoliciesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create policies internal server error response a status code equal to that given
func (o *CreatePoliciesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create policies internal server error response
func (o *CreatePoliciesInternalServerError) Code() int {
	return 500
}

func (o *CreatePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *CreatePoliciesInternalServerError) String() string {
	return fmt.Sprintf("[POST /container-security/entities/image-assessment-policies/v1][%d] createPoliciesInternalServerError  %+v", 500, o.Payload)
}

func (o *CreatePoliciesInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CreatePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CoreEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
