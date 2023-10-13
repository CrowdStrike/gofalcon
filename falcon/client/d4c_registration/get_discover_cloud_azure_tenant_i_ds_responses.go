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

// GetDiscoverCloudAzureTenantIDsReader is a Reader for the GetDiscoverCloudAzureTenantIDs structure.
type GetDiscoverCloudAzureTenantIDsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDiscoverCloudAzureTenantIDsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDiscoverCloudAzureTenantIDsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetDiscoverCloudAzureTenantIDsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDiscoverCloudAzureTenantIDsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDiscoverCloudAzureTenantIDsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetDiscoverCloudAzureTenantIDsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /cloud-connect-azure/entities/tenant-id/v1] GetDiscoverCloudAzureTenantIDs", response, response.Code())
	}
}

// NewGetDiscoverCloudAzureTenantIDsOK creates a GetDiscoverCloudAzureTenantIDsOK with default headers values
func NewGetDiscoverCloudAzureTenantIDsOK() *GetDiscoverCloudAzureTenantIDsOK {
	return &GetDiscoverCloudAzureTenantIDsOK{}
}

/* GetDiscoverCloudAzureTenantIDsOK describes a response with status code 200, with default header values.

OK
*/
type GetDiscoverCloudAzureTenantIDsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureTenantIDsResponseV1
}

// IsSuccess returns true when this get discover cloud azure tenant i ds o k response has a 2xx status code
func (o *GetDiscoverCloudAzureTenantIDsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get discover cloud azure tenant i ds o k response has a 3xx status code
func (o *GetDiscoverCloudAzureTenantIDsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get discover cloud azure tenant i ds o k response has a 4xx status code
func (o *GetDiscoverCloudAzureTenantIDsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get discover cloud azure tenant i ds o k response has a 5xx status code
func (o *GetDiscoverCloudAzureTenantIDsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get discover cloud azure tenant i ds o k response a status code equal to that given
func (o *GetDiscoverCloudAzureTenantIDsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get discover cloud azure tenant i ds o k response
func (o *GetDiscoverCloudAzureTenantIDsOK) Code() int {
	return 200
}

func (o *GetDiscoverCloudAzureTenantIDsOK) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsOK  %+v", 200, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsOK) String() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsOK  %+v", 200, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsOK) GetPayload() *models.RegistrationAzureTenantIDsResponseV1 {
	return o.Payload
}

func (o *GetDiscoverCloudAzureTenantIDsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureTenantIDsResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDiscoverCloudAzureTenantIDsBadRequest creates a GetDiscoverCloudAzureTenantIDsBadRequest with default headers values
func NewGetDiscoverCloudAzureTenantIDsBadRequest() *GetDiscoverCloudAzureTenantIDsBadRequest {
	return &GetDiscoverCloudAzureTenantIDsBadRequest{}
}

/* GetDiscoverCloudAzureTenantIDsBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetDiscoverCloudAzureTenantIDsBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureTenantIDsResponseV1
}

// IsSuccess returns true when this get discover cloud azure tenant i ds bad request response has a 2xx status code
func (o *GetDiscoverCloudAzureTenantIDsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get discover cloud azure tenant i ds bad request response has a 3xx status code
func (o *GetDiscoverCloudAzureTenantIDsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get discover cloud azure tenant i ds bad request response has a 4xx status code
func (o *GetDiscoverCloudAzureTenantIDsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get discover cloud azure tenant i ds bad request response has a 5xx status code
func (o *GetDiscoverCloudAzureTenantIDsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get discover cloud azure tenant i ds bad request response a status code equal to that given
func (o *GetDiscoverCloudAzureTenantIDsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get discover cloud azure tenant i ds bad request response
func (o *GetDiscoverCloudAzureTenantIDsBadRequest) Code() int {
	return 400
}

func (o *GetDiscoverCloudAzureTenantIDsBadRequest) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsBadRequest  %+v", 400, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsBadRequest) String() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsBadRequest  %+v", 400, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsBadRequest) GetPayload() *models.RegistrationAzureTenantIDsResponseV1 {
	return o.Payload
}

func (o *GetDiscoverCloudAzureTenantIDsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureTenantIDsResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDiscoverCloudAzureTenantIDsForbidden creates a GetDiscoverCloudAzureTenantIDsForbidden with default headers values
func NewGetDiscoverCloudAzureTenantIDsForbidden() *GetDiscoverCloudAzureTenantIDsForbidden {
	return &GetDiscoverCloudAzureTenantIDsForbidden{}
}

/* GetDiscoverCloudAzureTenantIDsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetDiscoverCloudAzureTenantIDsForbidden struct {

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

// IsSuccess returns true when this get discover cloud azure tenant i ds forbidden response has a 2xx status code
func (o *GetDiscoverCloudAzureTenantIDsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get discover cloud azure tenant i ds forbidden response has a 3xx status code
func (o *GetDiscoverCloudAzureTenantIDsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get discover cloud azure tenant i ds forbidden response has a 4xx status code
func (o *GetDiscoverCloudAzureTenantIDsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get discover cloud azure tenant i ds forbidden response has a 5xx status code
func (o *GetDiscoverCloudAzureTenantIDsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get discover cloud azure tenant i ds forbidden response a status code equal to that given
func (o *GetDiscoverCloudAzureTenantIDsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get discover cloud azure tenant i ds forbidden response
func (o *GetDiscoverCloudAzureTenantIDsForbidden) Code() int {
	return 403
}

func (o *GetDiscoverCloudAzureTenantIDsForbidden) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsForbidden  %+v", 403, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsForbidden) String() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsForbidden  %+v", 403, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetDiscoverCloudAzureTenantIDsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDiscoverCloudAzureTenantIDsTooManyRequests creates a GetDiscoverCloudAzureTenantIDsTooManyRequests with default headers values
func NewGetDiscoverCloudAzureTenantIDsTooManyRequests() *GetDiscoverCloudAzureTenantIDsTooManyRequests {
	return &GetDiscoverCloudAzureTenantIDsTooManyRequests{}
}

/* GetDiscoverCloudAzureTenantIDsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetDiscoverCloudAzureTenantIDsTooManyRequests struct {

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

// IsSuccess returns true when this get discover cloud azure tenant i ds too many requests response has a 2xx status code
func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get discover cloud azure tenant i ds too many requests response has a 3xx status code
func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get discover cloud azure tenant i ds too many requests response has a 4xx status code
func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get discover cloud azure tenant i ds too many requests response has a 5xx status code
func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get discover cloud azure tenant i ds too many requests response a status code equal to that given
func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get discover cloud azure tenant i ds too many requests response
func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) Code() int {
	return 429
}

func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetDiscoverCloudAzureTenantIDsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDiscoverCloudAzureTenantIDsInternalServerError creates a GetDiscoverCloudAzureTenantIDsInternalServerError with default headers values
func NewGetDiscoverCloudAzureTenantIDsInternalServerError() *GetDiscoverCloudAzureTenantIDsInternalServerError {
	return &GetDiscoverCloudAzureTenantIDsInternalServerError{}
}

/* GetDiscoverCloudAzureTenantIDsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetDiscoverCloudAzureTenantIDsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.RegistrationAzureTenantIDsResponseV1
}

// IsSuccess returns true when this get discover cloud azure tenant i ds internal server error response has a 2xx status code
func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get discover cloud azure tenant i ds internal server error response has a 3xx status code
func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get discover cloud azure tenant i ds internal server error response has a 4xx status code
func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get discover cloud azure tenant i ds internal server error response has a 5xx status code
func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get discover cloud azure tenant i ds internal server error response a status code equal to that given
func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get discover cloud azure tenant i ds internal server error response
func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) Code() int {
	return 500
}

func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsInternalServerError  %+v", 500, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) String() string {
	return fmt.Sprintf("[GET /cloud-connect-azure/entities/tenant-id/v1][%d] getDiscoverCloudAzureTenantIDsInternalServerError  %+v", 500, o.Payload)
}

func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) GetPayload() *models.RegistrationAzureTenantIDsResponseV1 {
	return o.Payload
}

func (o *GetDiscoverCloudAzureTenantIDsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.RegistrationAzureTenantIDsResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
