// Code generated by go-swagger; DO NOT EDIT.

package workflows

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

// WorkflowDefinitionsImportReader is a Reader for the WorkflowDefinitionsImport structure.
type WorkflowDefinitionsImportReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *WorkflowDefinitionsImportReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewWorkflowDefinitionsImportOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewWorkflowDefinitionsImportBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewWorkflowDefinitionsImportForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewWorkflowDefinitionsImportNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewWorkflowDefinitionsImportTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewWorkflowDefinitionsImportInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /workflows/entities/definitions/import/v1] WorkflowDefinitionsImport", response, response.Code())
	}
}

// NewWorkflowDefinitionsImportOK creates a WorkflowDefinitionsImportOK with default headers values
func NewWorkflowDefinitionsImportOK() *WorkflowDefinitionsImportOK {
	return &WorkflowDefinitionsImportOK{}
}

/*
WorkflowDefinitionsImportOK describes a response with status code 200, with default header values.

OK
*/
type WorkflowDefinitionsImportOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DefinitionsDefinitionImportResponse
}

// IsSuccess returns true when this workflow definitions import o k response has a 2xx status code
func (o *WorkflowDefinitionsImportOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this workflow definitions import o k response has a 3xx status code
func (o *WorkflowDefinitionsImportOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow definitions import o k response has a 4xx status code
func (o *WorkflowDefinitionsImportOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this workflow definitions import o k response has a 5xx status code
func (o *WorkflowDefinitionsImportOK) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow definitions import o k response a status code equal to that given
func (o *WorkflowDefinitionsImportOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the workflow definitions import o k response
func (o *WorkflowDefinitionsImportOK) Code() int {
	return 200
}

func (o *WorkflowDefinitionsImportOK) Error() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportOK  %+v", 200, o.Payload)
}

func (o *WorkflowDefinitionsImportOK) String() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportOK  %+v", 200, o.Payload)
}

func (o *WorkflowDefinitionsImportOK) GetPayload() *models.DefinitionsDefinitionImportResponse {
	return o.Payload
}

func (o *WorkflowDefinitionsImportOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DefinitionsDefinitionImportResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowDefinitionsImportBadRequest creates a WorkflowDefinitionsImportBadRequest with default headers values
func NewWorkflowDefinitionsImportBadRequest() *WorkflowDefinitionsImportBadRequest {
	return &WorkflowDefinitionsImportBadRequest{}
}

/*
WorkflowDefinitionsImportBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type WorkflowDefinitionsImportBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DefinitionsDefinitionImportResponse
}

// IsSuccess returns true when this workflow definitions import bad request response has a 2xx status code
func (o *WorkflowDefinitionsImportBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow definitions import bad request response has a 3xx status code
func (o *WorkflowDefinitionsImportBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow definitions import bad request response has a 4xx status code
func (o *WorkflowDefinitionsImportBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow definitions import bad request response has a 5xx status code
func (o *WorkflowDefinitionsImportBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow definitions import bad request response a status code equal to that given
func (o *WorkflowDefinitionsImportBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the workflow definitions import bad request response
func (o *WorkflowDefinitionsImportBadRequest) Code() int {
	return 400
}

func (o *WorkflowDefinitionsImportBadRequest) Error() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportBadRequest  %+v", 400, o.Payload)
}

func (o *WorkflowDefinitionsImportBadRequest) String() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportBadRequest  %+v", 400, o.Payload)
}

func (o *WorkflowDefinitionsImportBadRequest) GetPayload() *models.DefinitionsDefinitionImportResponse {
	return o.Payload
}

func (o *WorkflowDefinitionsImportBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DefinitionsDefinitionImportResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowDefinitionsImportForbidden creates a WorkflowDefinitionsImportForbidden with default headers values
func NewWorkflowDefinitionsImportForbidden() *WorkflowDefinitionsImportForbidden {
	return &WorkflowDefinitionsImportForbidden{}
}

/*
WorkflowDefinitionsImportForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type WorkflowDefinitionsImportForbidden struct {

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

// IsSuccess returns true when this workflow definitions import forbidden response has a 2xx status code
func (o *WorkflowDefinitionsImportForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow definitions import forbidden response has a 3xx status code
func (o *WorkflowDefinitionsImportForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow definitions import forbidden response has a 4xx status code
func (o *WorkflowDefinitionsImportForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow definitions import forbidden response has a 5xx status code
func (o *WorkflowDefinitionsImportForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow definitions import forbidden response a status code equal to that given
func (o *WorkflowDefinitionsImportForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the workflow definitions import forbidden response
func (o *WorkflowDefinitionsImportForbidden) Code() int {
	return 403
}

func (o *WorkflowDefinitionsImportForbidden) Error() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportForbidden  %+v", 403, o.Payload)
}

func (o *WorkflowDefinitionsImportForbidden) String() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportForbidden  %+v", 403, o.Payload)
}

func (o *WorkflowDefinitionsImportForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *WorkflowDefinitionsImportForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewWorkflowDefinitionsImportNotFound creates a WorkflowDefinitionsImportNotFound with default headers values
func NewWorkflowDefinitionsImportNotFound() *WorkflowDefinitionsImportNotFound {
	return &WorkflowDefinitionsImportNotFound{}
}

/*
WorkflowDefinitionsImportNotFound describes a response with status code 404, with default header values.

Not Found
*/
type WorkflowDefinitionsImportNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DefinitionsDefinitionImportResponse
}

// IsSuccess returns true when this workflow definitions import not found response has a 2xx status code
func (o *WorkflowDefinitionsImportNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow definitions import not found response has a 3xx status code
func (o *WorkflowDefinitionsImportNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow definitions import not found response has a 4xx status code
func (o *WorkflowDefinitionsImportNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow definitions import not found response has a 5xx status code
func (o *WorkflowDefinitionsImportNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow definitions import not found response a status code equal to that given
func (o *WorkflowDefinitionsImportNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the workflow definitions import not found response
func (o *WorkflowDefinitionsImportNotFound) Code() int {
	return 404
}

func (o *WorkflowDefinitionsImportNotFound) Error() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportNotFound  %+v", 404, o.Payload)
}

func (o *WorkflowDefinitionsImportNotFound) String() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportNotFound  %+v", 404, o.Payload)
}

func (o *WorkflowDefinitionsImportNotFound) GetPayload() *models.DefinitionsDefinitionImportResponse {
	return o.Payload
}

func (o *WorkflowDefinitionsImportNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DefinitionsDefinitionImportResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowDefinitionsImportTooManyRequests creates a WorkflowDefinitionsImportTooManyRequests with default headers values
func NewWorkflowDefinitionsImportTooManyRequests() *WorkflowDefinitionsImportTooManyRequests {
	return &WorkflowDefinitionsImportTooManyRequests{}
}

/*
WorkflowDefinitionsImportTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type WorkflowDefinitionsImportTooManyRequests struct {

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

// IsSuccess returns true when this workflow definitions import too many requests response has a 2xx status code
func (o *WorkflowDefinitionsImportTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow definitions import too many requests response has a 3xx status code
func (o *WorkflowDefinitionsImportTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow definitions import too many requests response has a 4xx status code
func (o *WorkflowDefinitionsImportTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow definitions import too many requests response has a 5xx status code
func (o *WorkflowDefinitionsImportTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow definitions import too many requests response a status code equal to that given
func (o *WorkflowDefinitionsImportTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the workflow definitions import too many requests response
func (o *WorkflowDefinitionsImportTooManyRequests) Code() int {
	return 429
}

func (o *WorkflowDefinitionsImportTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportTooManyRequests  %+v", 429, o.Payload)
}

func (o *WorkflowDefinitionsImportTooManyRequests) String() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportTooManyRequests  %+v", 429, o.Payload)
}

func (o *WorkflowDefinitionsImportTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *WorkflowDefinitionsImportTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewWorkflowDefinitionsImportInternalServerError creates a WorkflowDefinitionsImportInternalServerError with default headers values
func NewWorkflowDefinitionsImportInternalServerError() *WorkflowDefinitionsImportInternalServerError {
	return &WorkflowDefinitionsImportInternalServerError{}
}

/*
WorkflowDefinitionsImportInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type WorkflowDefinitionsImportInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DefinitionsDefinitionImportResponse
}

// IsSuccess returns true when this workflow definitions import internal server error response has a 2xx status code
func (o *WorkflowDefinitionsImportInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow definitions import internal server error response has a 3xx status code
func (o *WorkflowDefinitionsImportInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow definitions import internal server error response has a 4xx status code
func (o *WorkflowDefinitionsImportInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this workflow definitions import internal server error response has a 5xx status code
func (o *WorkflowDefinitionsImportInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this workflow definitions import internal server error response a status code equal to that given
func (o *WorkflowDefinitionsImportInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the workflow definitions import internal server error response
func (o *WorkflowDefinitionsImportInternalServerError) Code() int {
	return 500
}

func (o *WorkflowDefinitionsImportInternalServerError) Error() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportInternalServerError  %+v", 500, o.Payload)
}

func (o *WorkflowDefinitionsImportInternalServerError) String() string {
	return fmt.Sprintf("[POST /workflows/entities/definitions/import/v1][%d] workflowDefinitionsImportInternalServerError  %+v", 500, o.Payload)
}

func (o *WorkflowDefinitionsImportInternalServerError) GetPayload() *models.DefinitionsDefinitionImportResponse {
	return o.Payload
}

func (o *WorkflowDefinitionsImportInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DefinitionsDefinitionImportResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}