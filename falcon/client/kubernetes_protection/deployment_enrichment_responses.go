// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// DeploymentEnrichmentReader is a Reader for the DeploymentEnrichment structure.
type DeploymentEnrichmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeploymentEnrichmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeploymentEnrichmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewDeploymentEnrichmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeploymentEnrichmentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeploymentEnrichmentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/aggregates/enrichment/deployments/entities/v1] DeploymentEnrichment", response, response.Code())
	}
}

// NewDeploymentEnrichmentOK creates a DeploymentEnrichmentOK with default headers values
func NewDeploymentEnrichmentOK() *DeploymentEnrichmentOK {
	return &DeploymentEnrichmentOK{}
}

/*
DeploymentEnrichmentOK describes a response with status code 200, with default header values.

OK
*/
type DeploymentEnrichmentOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.K8sassetsDeploymentEnrichmentResponse
}

// IsSuccess returns true when this deployment enrichment o k response has a 2xx status code
func (o *DeploymentEnrichmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this deployment enrichment o k response has a 3xx status code
func (o *DeploymentEnrichmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deployment enrichment o k response has a 4xx status code
func (o *DeploymentEnrichmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this deployment enrichment o k response has a 5xx status code
func (o *DeploymentEnrichmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this deployment enrichment o k response a status code equal to that given
func (o *DeploymentEnrichmentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the deployment enrichment o k response
func (o *DeploymentEnrichmentOK) Code() int {
	return 200
}

func (o *DeploymentEnrichmentOK) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentOK  %+v", 200, o.Payload)
}

func (o *DeploymentEnrichmentOK) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentOK  %+v", 200, o.Payload)
}

func (o *DeploymentEnrichmentOK) GetPayload() *models.K8sassetsDeploymentEnrichmentResponse {
	return o.Payload
}

func (o *DeploymentEnrichmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.K8sassetsDeploymentEnrichmentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeploymentEnrichmentForbidden creates a DeploymentEnrichmentForbidden with default headers values
func NewDeploymentEnrichmentForbidden() *DeploymentEnrichmentForbidden {
	return &DeploymentEnrichmentForbidden{}
}

/*
DeploymentEnrichmentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeploymentEnrichmentForbidden struct {

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

// IsSuccess returns true when this deployment enrichment forbidden response has a 2xx status code
func (o *DeploymentEnrichmentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deployment enrichment forbidden response has a 3xx status code
func (o *DeploymentEnrichmentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deployment enrichment forbidden response has a 4xx status code
func (o *DeploymentEnrichmentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this deployment enrichment forbidden response has a 5xx status code
func (o *DeploymentEnrichmentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this deployment enrichment forbidden response a status code equal to that given
func (o *DeploymentEnrichmentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the deployment enrichment forbidden response
func (o *DeploymentEnrichmentForbidden) Code() int {
	return 403
}

func (o *DeploymentEnrichmentForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentForbidden  %+v", 403, o.Payload)
}

func (o *DeploymentEnrichmentForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentForbidden  %+v", 403, o.Payload)
}

func (o *DeploymentEnrichmentForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeploymentEnrichmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeploymentEnrichmentTooManyRequests creates a DeploymentEnrichmentTooManyRequests with default headers values
func NewDeploymentEnrichmentTooManyRequests() *DeploymentEnrichmentTooManyRequests {
	return &DeploymentEnrichmentTooManyRequests{}
}

/*
DeploymentEnrichmentTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type DeploymentEnrichmentTooManyRequests struct {

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

// IsSuccess returns true when this deployment enrichment too many requests response has a 2xx status code
func (o *DeploymentEnrichmentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deployment enrichment too many requests response has a 3xx status code
func (o *DeploymentEnrichmentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deployment enrichment too many requests response has a 4xx status code
func (o *DeploymentEnrichmentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this deployment enrichment too many requests response has a 5xx status code
func (o *DeploymentEnrichmentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this deployment enrichment too many requests response a status code equal to that given
func (o *DeploymentEnrichmentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the deployment enrichment too many requests response
func (o *DeploymentEnrichmentTooManyRequests) Code() int {
	return 429
}

func (o *DeploymentEnrichmentTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeploymentEnrichmentTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeploymentEnrichmentTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *DeploymentEnrichmentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewDeploymentEnrichmentInternalServerError creates a DeploymentEnrichmentInternalServerError with default headers values
func NewDeploymentEnrichmentInternalServerError() *DeploymentEnrichmentInternalServerError {
	return &DeploymentEnrichmentInternalServerError{}
}

/*
DeploymentEnrichmentInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeploymentEnrichmentInternalServerError struct {

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

// IsSuccess returns true when this deployment enrichment internal server error response has a 2xx status code
func (o *DeploymentEnrichmentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deployment enrichment internal server error response has a 3xx status code
func (o *DeploymentEnrichmentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deployment enrichment internal server error response has a 4xx status code
func (o *DeploymentEnrichmentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this deployment enrichment internal server error response has a 5xx status code
func (o *DeploymentEnrichmentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this deployment enrichment internal server error response a status code equal to that given
func (o *DeploymentEnrichmentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the deployment enrichment internal server error response
func (o *DeploymentEnrichmentInternalServerError) Code() int {
	return 500
}

func (o *DeploymentEnrichmentInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentInternalServerError  %+v", 500, o.Payload)
}

func (o *DeploymentEnrichmentInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/aggregates/enrichment/deployments/entities/v1][%d] deploymentEnrichmentInternalServerError  %+v", 500, o.Payload)
}

func (o *DeploymentEnrichmentInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *DeploymentEnrichmentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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