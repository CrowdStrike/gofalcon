// Code generated by go-swagger; DO NOT EDIT.

package a_s_p_m

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

// GetIntegrationTasksAdminReader is a Reader for the GetIntegrationTasksAdmin structure.
type GetIntegrationTasksAdminReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetIntegrationTasksAdminReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetIntegrationTasksAdminOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetIntegrationTasksAdminBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetIntegrationTasksAdminUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetIntegrationTasksAdminForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetIntegrationTasksAdminTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetIntegrationTasksAdminInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /aspm-api-gateway/api/v1/integration_tasks/admin] GetIntegrationTasksAdmin", response, response.Code())
	}
}

// NewGetIntegrationTasksAdminOK creates a GetIntegrationTasksAdminOK with default headers values
func NewGetIntegrationTasksAdminOK() *GetIntegrationTasksAdminOK {
	return &GetIntegrationTasksAdminOK{}
}

/*
GetIntegrationTasksAdminOK describes a response with status code 200, with default header values.

OK
*/
type GetIntegrationTasksAdminOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesListIntegrationTasksResponse
}

// IsSuccess returns true when this get integration tasks admin o k response has a 2xx status code
func (o *GetIntegrationTasksAdminOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get integration tasks admin o k response has a 3xx status code
func (o *GetIntegrationTasksAdminOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get integration tasks admin o k response has a 4xx status code
func (o *GetIntegrationTasksAdminOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get integration tasks admin o k response has a 5xx status code
func (o *GetIntegrationTasksAdminOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get integration tasks admin o k response a status code equal to that given
func (o *GetIntegrationTasksAdminOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get integration tasks admin o k response
func (o *GetIntegrationTasksAdminOK) Code() int {
	return 200
}

func (o *GetIntegrationTasksAdminOK) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminOK  %+v", 200, o.Payload)
}

func (o *GetIntegrationTasksAdminOK) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminOK  %+v", 200, o.Payload)
}

func (o *GetIntegrationTasksAdminOK) GetPayload() *models.TypesListIntegrationTasksResponse {
	return o.Payload
}

func (o *GetIntegrationTasksAdminOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesListIntegrationTasksResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIntegrationTasksAdminBadRequest creates a GetIntegrationTasksAdminBadRequest with default headers values
func NewGetIntegrationTasksAdminBadRequest() *GetIntegrationTasksAdminBadRequest {
	return &GetIntegrationTasksAdminBadRequest{}
}

/*
GetIntegrationTasksAdminBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetIntegrationTasksAdminBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get integration tasks admin bad request response has a 2xx status code
func (o *GetIntegrationTasksAdminBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get integration tasks admin bad request response has a 3xx status code
func (o *GetIntegrationTasksAdminBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get integration tasks admin bad request response has a 4xx status code
func (o *GetIntegrationTasksAdminBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get integration tasks admin bad request response has a 5xx status code
func (o *GetIntegrationTasksAdminBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get integration tasks admin bad request response a status code equal to that given
func (o *GetIntegrationTasksAdminBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get integration tasks admin bad request response
func (o *GetIntegrationTasksAdminBadRequest) Code() int {
	return 400
}

func (o *GetIntegrationTasksAdminBadRequest) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminBadRequest  %+v", 400, o.Payload)
}

func (o *GetIntegrationTasksAdminBadRequest) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminBadRequest  %+v", 400, o.Payload)
}

func (o *GetIntegrationTasksAdminBadRequest) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetIntegrationTasksAdminBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIntegrationTasksAdminUnauthorized creates a GetIntegrationTasksAdminUnauthorized with default headers values
func NewGetIntegrationTasksAdminUnauthorized() *GetIntegrationTasksAdminUnauthorized {
	return &GetIntegrationTasksAdminUnauthorized{}
}

/*
GetIntegrationTasksAdminUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetIntegrationTasksAdminUnauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get integration tasks admin unauthorized response has a 2xx status code
func (o *GetIntegrationTasksAdminUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get integration tasks admin unauthorized response has a 3xx status code
func (o *GetIntegrationTasksAdminUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get integration tasks admin unauthorized response has a 4xx status code
func (o *GetIntegrationTasksAdminUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get integration tasks admin unauthorized response has a 5xx status code
func (o *GetIntegrationTasksAdminUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get integration tasks admin unauthorized response a status code equal to that given
func (o *GetIntegrationTasksAdminUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get integration tasks admin unauthorized response
func (o *GetIntegrationTasksAdminUnauthorized) Code() int {
	return 401
}

func (o *GetIntegrationTasksAdminUnauthorized) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminUnauthorized  %+v", 401, o.Payload)
}

func (o *GetIntegrationTasksAdminUnauthorized) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminUnauthorized  %+v", 401, o.Payload)
}

func (o *GetIntegrationTasksAdminUnauthorized) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetIntegrationTasksAdminUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIntegrationTasksAdminForbidden creates a GetIntegrationTasksAdminForbidden with default headers values
func NewGetIntegrationTasksAdminForbidden() *GetIntegrationTasksAdminForbidden {
	return &GetIntegrationTasksAdminForbidden{}
}

/*
GetIntegrationTasksAdminForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetIntegrationTasksAdminForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get integration tasks admin forbidden response has a 2xx status code
func (o *GetIntegrationTasksAdminForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get integration tasks admin forbidden response has a 3xx status code
func (o *GetIntegrationTasksAdminForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get integration tasks admin forbidden response has a 4xx status code
func (o *GetIntegrationTasksAdminForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get integration tasks admin forbidden response has a 5xx status code
func (o *GetIntegrationTasksAdminForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get integration tasks admin forbidden response a status code equal to that given
func (o *GetIntegrationTasksAdminForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get integration tasks admin forbidden response
func (o *GetIntegrationTasksAdminForbidden) Code() int {
	return 403
}

func (o *GetIntegrationTasksAdminForbidden) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminForbidden  %+v", 403, o.Payload)
}

func (o *GetIntegrationTasksAdminForbidden) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminForbidden  %+v", 403, o.Payload)
}

func (o *GetIntegrationTasksAdminForbidden) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetIntegrationTasksAdminForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIntegrationTasksAdminTooManyRequests creates a GetIntegrationTasksAdminTooManyRequests with default headers values
func NewGetIntegrationTasksAdminTooManyRequests() *GetIntegrationTasksAdminTooManyRequests {
	return &GetIntegrationTasksAdminTooManyRequests{}
}

/*
GetIntegrationTasksAdminTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetIntegrationTasksAdminTooManyRequests struct {

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

// IsSuccess returns true when this get integration tasks admin too many requests response has a 2xx status code
func (o *GetIntegrationTasksAdminTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get integration tasks admin too many requests response has a 3xx status code
func (o *GetIntegrationTasksAdminTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get integration tasks admin too many requests response has a 4xx status code
func (o *GetIntegrationTasksAdminTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get integration tasks admin too many requests response has a 5xx status code
func (o *GetIntegrationTasksAdminTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get integration tasks admin too many requests response a status code equal to that given
func (o *GetIntegrationTasksAdminTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get integration tasks admin too many requests response
func (o *GetIntegrationTasksAdminTooManyRequests) Code() int {
	return 429
}

func (o *GetIntegrationTasksAdminTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetIntegrationTasksAdminTooManyRequests) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetIntegrationTasksAdminTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetIntegrationTasksAdminTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetIntegrationTasksAdminInternalServerError creates a GetIntegrationTasksAdminInternalServerError with default headers values
func NewGetIntegrationTasksAdminInternalServerError() *GetIntegrationTasksAdminInternalServerError {
	return &GetIntegrationTasksAdminInternalServerError{}
}

/*
GetIntegrationTasksAdminInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetIntegrationTasksAdminInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.TypesErrorMessage
}

// IsSuccess returns true when this get integration tasks admin internal server error response has a 2xx status code
func (o *GetIntegrationTasksAdminInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get integration tasks admin internal server error response has a 3xx status code
func (o *GetIntegrationTasksAdminInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get integration tasks admin internal server error response has a 4xx status code
func (o *GetIntegrationTasksAdminInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get integration tasks admin internal server error response has a 5xx status code
func (o *GetIntegrationTasksAdminInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get integration tasks admin internal server error response a status code equal to that given
func (o *GetIntegrationTasksAdminInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get integration tasks admin internal server error response
func (o *GetIntegrationTasksAdminInternalServerError) Code() int {
	return 500
}

func (o *GetIntegrationTasksAdminInternalServerError) Error() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminInternalServerError  %+v", 500, o.Payload)
}

func (o *GetIntegrationTasksAdminInternalServerError) String() string {
	return fmt.Sprintf("[GET /aspm-api-gateway/api/v1/integration_tasks/admin][%d] getIntegrationTasksAdminInternalServerError  %+v", 500, o.Payload)
}

func (o *GetIntegrationTasksAdminInternalServerError) GetPayload() *models.TypesErrorMessage {
	return o.Payload
}

func (o *GetIntegrationTasksAdminInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.TypesErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
