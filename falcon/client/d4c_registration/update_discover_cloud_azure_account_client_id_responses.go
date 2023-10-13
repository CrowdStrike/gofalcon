// Code generated by go-swagger; DO NOT EDIT.

package d4c_registration

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

// UpdateDiscoverCloudAzureAccountClientIDReader is a Reader for the UpdateDiscoverCloudAzureAccountClientID structure.
type UpdateDiscoverCloudAzureAccountClientIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateDiscoverCloudAzureAccountClientIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewUpdateDiscoverCloudAzureAccountClientIDCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateDiscoverCloudAzureAccountClientIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateDiscoverCloudAzureAccountClientIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateDiscoverCloudAzureAccountClientIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdateDiscoverCloudAzureAccountClientIDInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /cloud-connect-azure/entities/client-id/v1] UpdateDiscoverCloudAzureAccountClientID", response, response.Code())
	}
}

// NewUpdateDiscoverCloudAzureAccountClientIDCreated creates a UpdateDiscoverCloudAzureAccountClientIDCreated with default headers values
func NewUpdateDiscoverCloudAzureAccountClientIDCreated() *UpdateDiscoverCloudAzureAccountClientIDCreated {
	return &UpdateDiscoverCloudAzureAccountClientIDCreated{}
}

/* UpdateDiscoverCloudAzureAccountClientIDCreated describes a response with status code 201, with default header values.

Created
*/
type UpdateDiscoverCloudAzureAccountClientIDCreated struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureTenantConfigurationResponseV1
}

// IsSuccess returns true when this update discover cloud azure account client Id created response has a 2xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update discover cloud azure account client Id created response has a 3xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update discover cloud azure account client Id created response has a 4xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this update discover cloud azure account client Id created response has a 5xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this update discover cloud azure account client Id created response a status code equal to that given
func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the update discover cloud azure account client Id created response
func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) Code() int {
	return 201
}

func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdCreated  %+v", 201, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdCreated  %+v", 201, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) GetPayload() *models.RegistrationAzureTenantConfigurationResponseV1 {
	return o.Payload
}

func (o *UpdateDiscoverCloudAzureAccountClientIDCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureTenantConfigurationResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateDiscoverCloudAzureAccountClientIDBadRequest creates a UpdateDiscoverCloudAzureAccountClientIDBadRequest with default headers values
func NewUpdateDiscoverCloudAzureAccountClientIDBadRequest() *UpdateDiscoverCloudAzureAccountClientIDBadRequest {
	return &UpdateDiscoverCloudAzureAccountClientIDBadRequest{}
}

/* UpdateDiscoverCloudAzureAccountClientIDBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type UpdateDiscoverCloudAzureAccountClientIDBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureTenantConfigurationResponseV1
}

// IsSuccess returns true when this update discover cloud azure account client Id bad request response has a 2xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update discover cloud azure account client Id bad request response has a 3xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update discover cloud azure account client Id bad request response has a 4xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update discover cloud azure account client Id bad request response has a 5xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update discover cloud azure account client Id bad request response a status code equal to that given
func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update discover cloud azure account client Id bad request response
func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) Code() int {
	return 400
}

func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) GetPayload() *models.RegistrationAzureTenantConfigurationResponseV1 {
	return o.Payload
}

func (o *UpdateDiscoverCloudAzureAccountClientIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureTenantConfigurationResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateDiscoverCloudAzureAccountClientIDForbidden creates a UpdateDiscoverCloudAzureAccountClientIDForbidden with default headers values
func NewUpdateDiscoverCloudAzureAccountClientIDForbidden() *UpdateDiscoverCloudAzureAccountClientIDForbidden {
	return &UpdateDiscoverCloudAzureAccountClientIDForbidden{}
}

/* UpdateDiscoverCloudAzureAccountClientIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateDiscoverCloudAzureAccountClientIDForbidden struct {

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

// IsSuccess returns true when this update discover cloud azure account client Id forbidden response has a 2xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update discover cloud azure account client Id forbidden response has a 3xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update discover cloud azure account client Id forbidden response has a 4xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update discover cloud azure account client Id forbidden response has a 5xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update discover cloud azure account client Id forbidden response a status code equal to that given
func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update discover cloud azure account client Id forbidden response
func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) Code() int {
	return 403
}

func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdForbidden  %+v", 403, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdForbidden  %+v", 403, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDiscoverCloudAzureAccountClientIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateDiscoverCloudAzureAccountClientIDTooManyRequests creates a UpdateDiscoverCloudAzureAccountClientIDTooManyRequests with default headers values
func NewUpdateDiscoverCloudAzureAccountClientIDTooManyRequests() *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests {
	return &UpdateDiscoverCloudAzureAccountClientIDTooManyRequests{}
}

/* UpdateDiscoverCloudAzureAccountClientIDTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type UpdateDiscoverCloudAzureAccountClientIDTooManyRequests struct {

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

// IsSuccess returns true when this update discover cloud azure account client Id too many requests response has a 2xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update discover cloud azure account client Id too many requests response has a 3xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update discover cloud azure account client Id too many requests response has a 4xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update discover cloud azure account client Id too many requests response has a 5xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update discover cloud azure account client Id too many requests response a status code equal to that given
func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update discover cloud azure account client Id too many requests response
func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) Code() int {
	return 429
}

func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *UpdateDiscoverCloudAzureAccountClientIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateDiscoverCloudAzureAccountClientIDInternalServerError creates a UpdateDiscoverCloudAzureAccountClientIDInternalServerError with default headers values
func NewUpdateDiscoverCloudAzureAccountClientIDInternalServerError() *UpdateDiscoverCloudAzureAccountClientIDInternalServerError {
	return &UpdateDiscoverCloudAzureAccountClientIDInternalServerError{}
}

/* UpdateDiscoverCloudAzureAccountClientIDInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type UpdateDiscoverCloudAzureAccountClientIDInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureTenantConfigurationResponseV1
}

// IsSuccess returns true when this update discover cloud azure account client Id internal server error response has a 2xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update discover cloud azure account client Id internal server error response has a 3xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update discover cloud azure account client Id internal server error response has a 4xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this update discover cloud azure account client Id internal server error response has a 5xx status code
func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this update discover cloud azure account client Id internal server error response a status code equal to that given
func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the update discover cloud azure account client Id internal server error response
func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) Code() int {
	return 500
}

func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /cloud-connect-azure/entities/client-id/v1][%d] updateDiscoverCloudAzureAccountClientIdInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) GetPayload() *models.RegistrationAzureTenantConfigurationResponseV1 {
	return o.Payload
}

func (o *UpdateDiscoverCloudAzureAccountClientIDInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureTenantConfigurationResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
