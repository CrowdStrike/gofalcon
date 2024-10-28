// Code generated by go-swagger; DO NOT EDIT.

package container_images

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

// CombinedBaseImagesReader is a Reader for the CombinedBaseImages structure.
type CombinedBaseImagesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CombinedBaseImagesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCombinedBaseImagesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCombinedBaseImagesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCombinedBaseImagesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCombinedBaseImagesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCombinedBaseImagesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/combined/base-images/v1] CombinedBaseImages", response, response.Code())
	}
}

// NewCombinedBaseImagesOK creates a CombinedBaseImagesOK with default headers values
func NewCombinedBaseImagesOK() *CombinedBaseImagesOK {
	return &CombinedBaseImagesOK{}
}

/*
CombinedBaseImagesOK describes a response with status code 200, with default header values.

Created
*/
type CombinedBaseImagesOK struct {

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

// IsSuccess returns true when this combined base images o k response has a 2xx status code
func (o *CombinedBaseImagesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this combined base images o k response has a 3xx status code
func (o *CombinedBaseImagesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined base images o k response has a 4xx status code
func (o *CombinedBaseImagesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this combined base images o k response has a 5xx status code
func (o *CombinedBaseImagesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this combined base images o k response a status code equal to that given
func (o *CombinedBaseImagesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the combined base images o k response
func (o *CombinedBaseImagesOK) Code() int {
	return 200
}

func (o *CombinedBaseImagesOK) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesOK  %+v", 200, o.Payload)
}

func (o *CombinedBaseImagesOK) String() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesOK  %+v", 200, o.Payload)
}

func (o *CombinedBaseImagesOK) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CombinedBaseImagesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCombinedBaseImagesBadRequest creates a CombinedBaseImagesBadRequest with default headers values
func NewCombinedBaseImagesBadRequest() *CombinedBaseImagesBadRequest {
	return &CombinedBaseImagesBadRequest{}
}

/*
CombinedBaseImagesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CombinedBaseImagesBadRequest struct {

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

// IsSuccess returns true when this combined base images bad request response has a 2xx status code
func (o *CombinedBaseImagesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined base images bad request response has a 3xx status code
func (o *CombinedBaseImagesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined base images bad request response has a 4xx status code
func (o *CombinedBaseImagesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this combined base images bad request response has a 5xx status code
func (o *CombinedBaseImagesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this combined base images bad request response a status code equal to that given
func (o *CombinedBaseImagesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the combined base images bad request response
func (o *CombinedBaseImagesBadRequest) Code() int {
	return 400
}

func (o *CombinedBaseImagesBadRequest) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesBadRequest  %+v", 400, o.Payload)
}

func (o *CombinedBaseImagesBadRequest) String() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesBadRequest  %+v", 400, o.Payload)
}

func (o *CombinedBaseImagesBadRequest) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CombinedBaseImagesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCombinedBaseImagesForbidden creates a CombinedBaseImagesForbidden with default headers values
func NewCombinedBaseImagesForbidden() *CombinedBaseImagesForbidden {
	return &CombinedBaseImagesForbidden{}
}

/*
CombinedBaseImagesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CombinedBaseImagesForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaAPIError
}

// IsSuccess returns true when this combined base images forbidden response has a 2xx status code
func (o *CombinedBaseImagesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined base images forbidden response has a 3xx status code
func (o *CombinedBaseImagesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined base images forbidden response has a 4xx status code
func (o *CombinedBaseImagesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this combined base images forbidden response has a 5xx status code
func (o *CombinedBaseImagesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this combined base images forbidden response a status code equal to that given
func (o *CombinedBaseImagesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the combined base images forbidden response
func (o *CombinedBaseImagesForbidden) Code() int {
	return 403
}

func (o *CombinedBaseImagesForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesForbidden  %+v", 403, o.Payload)
}

func (o *CombinedBaseImagesForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesForbidden  %+v", 403, o.Payload)
}

func (o *CombinedBaseImagesForbidden) GetPayload() *models.MsaAPIError {
	return o.Payload
}

func (o *CombinedBaseImagesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaAPIError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCombinedBaseImagesTooManyRequests creates a CombinedBaseImagesTooManyRequests with default headers values
func NewCombinedBaseImagesTooManyRequests() *CombinedBaseImagesTooManyRequests {
	return &CombinedBaseImagesTooManyRequests{}
}

/*
CombinedBaseImagesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CombinedBaseImagesTooManyRequests struct {

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

// IsSuccess returns true when this combined base images too many requests response has a 2xx status code
func (o *CombinedBaseImagesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined base images too many requests response has a 3xx status code
func (o *CombinedBaseImagesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined base images too many requests response has a 4xx status code
func (o *CombinedBaseImagesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this combined base images too many requests response has a 5xx status code
func (o *CombinedBaseImagesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this combined base images too many requests response a status code equal to that given
func (o *CombinedBaseImagesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the combined base images too many requests response
func (o *CombinedBaseImagesTooManyRequests) Code() int {
	return 429
}

func (o *CombinedBaseImagesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CombinedBaseImagesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CombinedBaseImagesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CombinedBaseImagesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCombinedBaseImagesInternalServerError creates a CombinedBaseImagesInternalServerError with default headers values
func NewCombinedBaseImagesInternalServerError() *CombinedBaseImagesInternalServerError {
	return &CombinedBaseImagesInternalServerError{}
}

/*
CombinedBaseImagesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CombinedBaseImagesInternalServerError struct {

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

// IsSuccess returns true when this combined base images internal server error response has a 2xx status code
func (o *CombinedBaseImagesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this combined base images internal server error response has a 3xx status code
func (o *CombinedBaseImagesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this combined base images internal server error response has a 4xx status code
func (o *CombinedBaseImagesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this combined base images internal server error response has a 5xx status code
func (o *CombinedBaseImagesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this combined base images internal server error response a status code equal to that given
func (o *CombinedBaseImagesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the combined base images internal server error response
func (o *CombinedBaseImagesInternalServerError) Code() int {
	return 500
}

func (o *CombinedBaseImagesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesInternalServerError  %+v", 500, o.Payload)
}

func (o *CombinedBaseImagesInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/combined/base-images/v1][%d] combinedBaseImagesInternalServerError  %+v", 500, o.Payload)
}

func (o *CombinedBaseImagesInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CombinedBaseImagesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
