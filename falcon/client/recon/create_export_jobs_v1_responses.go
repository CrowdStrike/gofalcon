// Code generated by go-swagger; DO NOT EDIT.

package recon

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

// CreateExportJobsV1Reader is a Reader for the CreateExportJobsV1 structure.
type CreateExportJobsV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateExportJobsV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateExportJobsV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateExportJobsV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateExportJobsV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateExportJobsV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateExportJobsV1NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateExportJobsV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateExportJobsV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /recon/entities/exports/v1] CreateExportJobsV1", response, response.Code())
	}
}

// NewCreateExportJobsV1OK creates a CreateExportJobsV1OK with default headers values
func NewCreateExportJobsV1OK() *CreateExportJobsV1OK {
	return &CreateExportJobsV1OK{}
}

/*
CreateExportJobsV1OK describes a response with status code 200, with default header values.

OK
*/
type CreateExportJobsV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainLaunchExportJobResponseV1
}

// IsSuccess returns true when this create export jobs v1 o k response has a 2xx status code
func (o *CreateExportJobsV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create export jobs v1 o k response has a 3xx status code
func (o *CreateExportJobsV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 o k response has a 4xx status code
func (o *CreateExportJobsV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create export jobs v1 o k response has a 5xx status code
func (o *CreateExportJobsV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this create export jobs v1 o k response a status code equal to that given
func (o *CreateExportJobsV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create export jobs v1 o k response
func (o *CreateExportJobsV1OK) Code() int {
	return 200
}

func (o *CreateExportJobsV1OK) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1OK  %+v", 200, o.Payload)
}

func (o *CreateExportJobsV1OK) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1OK  %+v", 200, o.Payload)
}

func (o *CreateExportJobsV1OK) GetPayload() *models.DomainLaunchExportJobResponseV1 {
	return o.Payload
}

func (o *CreateExportJobsV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainLaunchExportJobResponseV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExportJobsV1BadRequest creates a CreateExportJobsV1BadRequest with default headers values
func NewCreateExportJobsV1BadRequest() *CreateExportJobsV1BadRequest {
	return &CreateExportJobsV1BadRequest{}
}

/*
CreateExportJobsV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type CreateExportJobsV1BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this create export jobs v1 bad request response has a 2xx status code
func (o *CreateExportJobsV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create export jobs v1 bad request response has a 3xx status code
func (o *CreateExportJobsV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 bad request response has a 4xx status code
func (o *CreateExportJobsV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create export jobs v1 bad request response has a 5xx status code
func (o *CreateExportJobsV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create export jobs v1 bad request response a status code equal to that given
func (o *CreateExportJobsV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create export jobs v1 bad request response
func (o *CreateExportJobsV1BadRequest) Code() int {
	return 400
}

func (o *CreateExportJobsV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1BadRequest  %+v", 400, o.Payload)
}

func (o *CreateExportJobsV1BadRequest) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1BadRequest  %+v", 400, o.Payload)
}

func (o *CreateExportJobsV1BadRequest) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *CreateExportJobsV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExportJobsV1Unauthorized creates a CreateExportJobsV1Unauthorized with default headers values
func NewCreateExportJobsV1Unauthorized() *CreateExportJobsV1Unauthorized {
	return &CreateExportJobsV1Unauthorized{}
}

/*
CreateExportJobsV1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateExportJobsV1Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this create export jobs v1 unauthorized response has a 2xx status code
func (o *CreateExportJobsV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create export jobs v1 unauthorized response has a 3xx status code
func (o *CreateExportJobsV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 unauthorized response has a 4xx status code
func (o *CreateExportJobsV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create export jobs v1 unauthorized response has a 5xx status code
func (o *CreateExportJobsV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create export jobs v1 unauthorized response a status code equal to that given
func (o *CreateExportJobsV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create export jobs v1 unauthorized response
func (o *CreateExportJobsV1Unauthorized) Code() int {
	return 401
}

func (o *CreateExportJobsV1Unauthorized) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1Unauthorized  %+v", 401, o.Payload)
}

func (o *CreateExportJobsV1Unauthorized) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1Unauthorized  %+v", 401, o.Payload)
}

func (o *CreateExportJobsV1Unauthorized) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *CreateExportJobsV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExportJobsV1Forbidden creates a CreateExportJobsV1Forbidden with default headers values
func NewCreateExportJobsV1Forbidden() *CreateExportJobsV1Forbidden {
	return &CreateExportJobsV1Forbidden{}
}

/*
CreateExportJobsV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateExportJobsV1Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this create export jobs v1 forbidden response has a 2xx status code
func (o *CreateExportJobsV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create export jobs v1 forbidden response has a 3xx status code
func (o *CreateExportJobsV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 forbidden response has a 4xx status code
func (o *CreateExportJobsV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create export jobs v1 forbidden response has a 5xx status code
func (o *CreateExportJobsV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create export jobs v1 forbidden response a status code equal to that given
func (o *CreateExportJobsV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create export jobs v1 forbidden response
func (o *CreateExportJobsV1Forbidden) Code() int {
	return 403
}

func (o *CreateExportJobsV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1Forbidden  %+v", 403, o.Payload)
}

func (o *CreateExportJobsV1Forbidden) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1Forbidden  %+v", 403, o.Payload)
}

func (o *CreateExportJobsV1Forbidden) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *CreateExportJobsV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExportJobsV1NotFound creates a CreateExportJobsV1NotFound with default headers values
func NewCreateExportJobsV1NotFound() *CreateExportJobsV1NotFound {
	return &CreateExportJobsV1NotFound{}
}

/*
CreateExportJobsV1NotFound describes a response with status code 404, with default header values.

Not Found
*/
type CreateExportJobsV1NotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this create export jobs v1 not found response has a 2xx status code
func (o *CreateExportJobsV1NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create export jobs v1 not found response has a 3xx status code
func (o *CreateExportJobsV1NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 not found response has a 4xx status code
func (o *CreateExportJobsV1NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create export jobs v1 not found response has a 5xx status code
func (o *CreateExportJobsV1NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create export jobs v1 not found response a status code equal to that given
func (o *CreateExportJobsV1NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create export jobs v1 not found response
func (o *CreateExportJobsV1NotFound) Code() int {
	return 404
}

func (o *CreateExportJobsV1NotFound) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1NotFound  %+v", 404, o.Payload)
}

func (o *CreateExportJobsV1NotFound) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1NotFound  %+v", 404, o.Payload)
}

func (o *CreateExportJobsV1NotFound) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *CreateExportJobsV1NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExportJobsV1TooManyRequests creates a CreateExportJobsV1TooManyRequests with default headers values
func NewCreateExportJobsV1TooManyRequests() *CreateExportJobsV1TooManyRequests {
	return &CreateExportJobsV1TooManyRequests{}
}

/*
CreateExportJobsV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateExportJobsV1TooManyRequests struct {

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

// IsSuccess returns true when this create export jobs v1 too many requests response has a 2xx status code
func (o *CreateExportJobsV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create export jobs v1 too many requests response has a 3xx status code
func (o *CreateExportJobsV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 too many requests response has a 4xx status code
func (o *CreateExportJobsV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create export jobs v1 too many requests response has a 5xx status code
func (o *CreateExportJobsV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create export jobs v1 too many requests response a status code equal to that given
func (o *CreateExportJobsV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create export jobs v1 too many requests response
func (o *CreateExportJobsV1TooManyRequests) Code() int {
	return 429
}

func (o *CreateExportJobsV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateExportJobsV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateExportJobsV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *CreateExportJobsV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateExportJobsV1InternalServerError creates a CreateExportJobsV1InternalServerError with default headers values
func NewCreateExportJobsV1InternalServerError() *CreateExportJobsV1InternalServerError {
	return &CreateExportJobsV1InternalServerError{}
}

/*
CreateExportJobsV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateExportJobsV1InternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainErrorsOnly
}

// IsSuccess returns true when this create export jobs v1 internal server error response has a 2xx status code
func (o *CreateExportJobsV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create export jobs v1 internal server error response has a 3xx status code
func (o *CreateExportJobsV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create export jobs v1 internal server error response has a 4xx status code
func (o *CreateExportJobsV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create export jobs v1 internal server error response has a 5xx status code
func (o *CreateExportJobsV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create export jobs v1 internal server error response a status code equal to that given
func (o *CreateExportJobsV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create export jobs v1 internal server error response
func (o *CreateExportJobsV1InternalServerError) Code() int {
	return 500
}

func (o *CreateExportJobsV1InternalServerError) Error() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1InternalServerError  %+v", 500, o.Payload)
}

func (o *CreateExportJobsV1InternalServerError) String() string {
	return fmt.Sprintf("[POST /recon/entities/exports/v1][%d] createExportJobsV1InternalServerError  %+v", 500, o.Payload)
}

func (o *CreateExportJobsV1InternalServerError) GetPayload() *models.DomainErrorsOnly {
	return o.Payload
}

func (o *CreateExportJobsV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
