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

// CreateBaseImagesEntitiesReader is a Reader for the CreateBaseImagesEntities structure.
type CreateBaseImagesEntitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateBaseImagesEntitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateBaseImagesEntitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateBaseImagesEntitiesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateBaseImagesEntitiesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateBaseImagesEntitiesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateBaseImagesEntitiesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /container-security/entities/base-images/v1] CreateBaseImagesEntities", response, response.Code())
	}
}

// NewCreateBaseImagesEntitiesOK creates a CreateBaseImagesEntitiesOK with default headers values
func NewCreateBaseImagesEntitiesOK() *CreateBaseImagesEntitiesOK {
	return &CreateBaseImagesEntitiesOK{}
}

/*
CreateBaseImagesEntitiesOK describes a response with status code 200, with default header values.

Created
*/
type CreateBaseImagesEntitiesOK struct {

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

// IsSuccess returns true when this create base images entities o k response has a 2xx status code
func (o *CreateBaseImagesEntitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create base images entities o k response has a 3xx status code
func (o *CreateBaseImagesEntitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create base images entities o k response has a 4xx status code
func (o *CreateBaseImagesEntitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create base images entities o k response has a 5xx status code
func (o *CreateBaseImagesEntitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create base images entities o k response a status code equal to that given
func (o *CreateBaseImagesEntitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create base images entities o k response
func (o *CreateBaseImagesEntitiesOK) Code() int {
	return 200
}

func (o *CreateBaseImagesEntitiesOK) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesOK  %+v", 200, o.Payload)
}

func (o *CreateBaseImagesEntitiesOK) String() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesOK  %+v", 200, o.Payload)
}

func (o *CreateBaseImagesEntitiesOK) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CreateBaseImagesEntitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateBaseImagesEntitiesBadRequest creates a CreateBaseImagesEntitiesBadRequest with default headers values
func NewCreateBaseImagesEntitiesBadRequest() *CreateBaseImagesEntitiesBadRequest {
	return &CreateBaseImagesEntitiesBadRequest{}
}

/*
CreateBaseImagesEntitiesBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateBaseImagesEntitiesBadRequest struct {

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

// IsSuccess returns true when this create base images entities bad request response has a 2xx status code
func (o *CreateBaseImagesEntitiesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create base images entities bad request response has a 3xx status code
func (o *CreateBaseImagesEntitiesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create base images entities bad request response has a 4xx status code
func (o *CreateBaseImagesEntitiesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create base images entities bad request response has a 5xx status code
func (o *CreateBaseImagesEntitiesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create base images entities bad request response a status code equal to that given
func (o *CreateBaseImagesEntitiesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create base images entities bad request response
func (o *CreateBaseImagesEntitiesBadRequest) Code() int {
	return 400
}

func (o *CreateBaseImagesEntitiesBadRequest) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesBadRequest  %+v", 400, o.Payload)
}

func (o *CreateBaseImagesEntitiesBadRequest) String() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesBadRequest  %+v", 400, o.Payload)
}

func (o *CreateBaseImagesEntitiesBadRequest) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CreateBaseImagesEntitiesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateBaseImagesEntitiesForbidden creates a CreateBaseImagesEntitiesForbidden with default headers values
func NewCreateBaseImagesEntitiesForbidden() *CreateBaseImagesEntitiesForbidden {
	return &CreateBaseImagesEntitiesForbidden{}
}

/*
CreateBaseImagesEntitiesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateBaseImagesEntitiesForbidden struct {

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

// IsSuccess returns true when this create base images entities forbidden response has a 2xx status code
func (o *CreateBaseImagesEntitiesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create base images entities forbidden response has a 3xx status code
func (o *CreateBaseImagesEntitiesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create base images entities forbidden response has a 4xx status code
func (o *CreateBaseImagesEntitiesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create base images entities forbidden response has a 5xx status code
func (o *CreateBaseImagesEntitiesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create base images entities forbidden response a status code equal to that given
func (o *CreateBaseImagesEntitiesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create base images entities forbidden response
func (o *CreateBaseImagesEntitiesForbidden) Code() int {
	return 403
}

func (o *CreateBaseImagesEntitiesForbidden) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *CreateBaseImagesEntitiesForbidden) String() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *CreateBaseImagesEntitiesForbidden) GetPayload() *models.MsaAPIError {
	return o.Payload
}

func (o *CreateBaseImagesEntitiesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateBaseImagesEntitiesTooManyRequests creates a CreateBaseImagesEntitiesTooManyRequests with default headers values
func NewCreateBaseImagesEntitiesTooManyRequests() *CreateBaseImagesEntitiesTooManyRequests {
	return &CreateBaseImagesEntitiesTooManyRequests{}
}

/*
CreateBaseImagesEntitiesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateBaseImagesEntitiesTooManyRequests struct {

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

// IsSuccess returns true when this create base images entities too many requests response has a 2xx status code
func (o *CreateBaseImagesEntitiesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create base images entities too many requests response has a 3xx status code
func (o *CreateBaseImagesEntitiesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create base images entities too many requests response has a 4xx status code
func (o *CreateBaseImagesEntitiesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create base images entities too many requests response has a 5xx status code
func (o *CreateBaseImagesEntitiesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create base images entities too many requests response a status code equal to that given
func (o *CreateBaseImagesEntitiesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create base images entities too many requests response
func (o *CreateBaseImagesEntitiesTooManyRequests) Code() int {
	return 429
}

func (o *CreateBaseImagesEntitiesTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateBaseImagesEntitiesTooManyRequests) String() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateBaseImagesEntitiesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateBaseImagesEntitiesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateBaseImagesEntitiesInternalServerError creates a CreateBaseImagesEntitiesInternalServerError with default headers values
func NewCreateBaseImagesEntitiesInternalServerError() *CreateBaseImagesEntitiesInternalServerError {
	return &CreateBaseImagesEntitiesInternalServerError{}
}

/*
CreateBaseImagesEntitiesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateBaseImagesEntitiesInternalServerError struct {

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

// IsSuccess returns true when this create base images entities internal server error response has a 2xx status code
func (o *CreateBaseImagesEntitiesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create base images entities internal server error response has a 3xx status code
func (o *CreateBaseImagesEntitiesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create base images entities internal server error response has a 4xx status code
func (o *CreateBaseImagesEntitiesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create base images entities internal server error response has a 5xx status code
func (o *CreateBaseImagesEntitiesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create base images entities internal server error response a status code equal to that given
func (o *CreateBaseImagesEntitiesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create base images entities internal server error response
func (o *CreateBaseImagesEntitiesInternalServerError) Code() int {
	return 500
}

func (o *CreateBaseImagesEntitiesInternalServerError) Error() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateBaseImagesEntitiesInternalServerError) String() string {
	return fmt.Sprintf("[POST /container-security/entities/base-images/v1][%d] createBaseImagesEntitiesInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateBaseImagesEntitiesInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *CreateBaseImagesEntitiesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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