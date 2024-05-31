// Code generated by go-swagger; DO NOT EDIT.

package identity_entities

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

// APIIdpEntitiesExplorerAPIUpdateEntitiesReader is a Reader for the APIIdpEntitiesExplorerAPIUpdateEntities structure.
type APIIdpEntitiesExplorerAPIUpdateEntitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAPIIdpEntitiesExplorerAPIUpdateEntitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewAPIIdpEntitiesExplorerAPIUpdateEntitiesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAPIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /idp-entities-explorer/entities/entities/v1] api.idp-entities-explorer.api.update-entities", response, response.Code())
	}
}

// NewAPIIdpEntitiesExplorerAPIUpdateEntitiesOK creates a APIIdpEntitiesExplorerAPIUpdateEntitiesOK with default headers values
func NewAPIIdpEntitiesExplorerAPIUpdateEntitiesOK() *APIIdpEntitiesExplorerAPIUpdateEntitiesOK {
	return &APIIdpEntitiesExplorerAPIUpdateEntitiesOK{}
}

/*
APIIdpEntitiesExplorerAPIUpdateEntitiesOK describes a response with status code 200, with default header values.

OK
*/
type APIIdpEntitiesExplorerAPIUpdateEntitiesOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.EntitiesEntitiesUpdateResponse
}

// IsSuccess returns true when this api idp entities explorer Api update entities o k response has a 2xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this api idp entities explorer Api update entities o k response has a 3xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api idp entities explorer Api update entities o k response has a 4xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this api idp entities explorer Api update entities o k response has a 5xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this api idp entities explorer Api update entities o k response a status code equal to that given
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the api idp entities explorer Api update entities o k response
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) Code() int {
	return 200
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) Error() string {
	return fmt.Sprintf("[PATCH /idp-entities-explorer/entities/entities/v1][%d] apiIdpEntitiesExplorerApiUpdateEntitiesOK  %+v", 200, o.Payload)
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) String() string {
	return fmt.Sprintf("[PATCH /idp-entities-explorer/entities/entities/v1][%d] apiIdpEntitiesExplorerApiUpdateEntitiesOK  %+v", 200, o.Payload)
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) GetPayload() *models.EntitiesEntitiesUpdateResponse {
	return o.Payload
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.EntitiesEntitiesUpdateResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAPIIdpEntitiesExplorerAPIUpdateEntitiesForbidden creates a APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden with default headers values
func NewAPIIdpEntitiesExplorerAPIUpdateEntitiesForbidden() *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden {
	return &APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden{}
}

/*
APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden struct {

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

// IsSuccess returns true when this api idp entities explorer Api update entities forbidden response has a 2xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this api idp entities explorer Api update entities forbidden response has a 3xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api idp entities explorer Api update entities forbidden response has a 4xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this api idp entities explorer Api update entities forbidden response has a 5xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this api idp entities explorer Api update entities forbidden response a status code equal to that given
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the api idp entities explorer Api update entities forbidden response
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) Code() int {
	return 403
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) Error() string {
	return fmt.Sprintf("[PATCH /idp-entities-explorer/entities/entities/v1][%d] apiIdpEntitiesExplorerApiUpdateEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) String() string {
	return fmt.Sprintf("[PATCH /idp-entities-explorer/entities/entities/v1][%d] apiIdpEntitiesExplorerApiUpdateEntitiesForbidden  %+v", 403, o.Payload)
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAPIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests creates a APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests with default headers values
func NewAPIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests() *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests {
	return &APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests{}
}

/*
APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests struct {

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

// IsSuccess returns true when this api idp entities explorer Api update entities too many requests response has a 2xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this api idp entities explorer Api update entities too many requests response has a 3xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this api idp entities explorer Api update entities too many requests response has a 4xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this api idp entities explorer Api update entities too many requests response has a 5xx status code
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this api idp entities explorer Api update entities too many requests response a status code equal to that given
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the api idp entities explorer Api update entities too many requests response
func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) Code() int {
	return 429
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /idp-entities-explorer/entities/entities/v1][%d] apiIdpEntitiesExplorerApiUpdateEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /idp-entities-explorer/entities/entities/v1][%d] apiIdpEntitiesExplorerApiUpdateEntitiesTooManyRequests  %+v", 429, o.Payload)
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *APIIdpEntitiesExplorerAPIUpdateEntitiesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
