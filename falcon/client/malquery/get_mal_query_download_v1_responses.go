// Code generated by go-swagger; DO NOT EDIT.

package malquery

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

// GetMalQueryDownloadV1Reader is a Reader for the GetMalQueryDownloadV1 structure.
type GetMalQueryDownloadV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMalQueryDownloadV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMalQueryDownloadV1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetMalQueryDownloadV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetMalQueryDownloadV1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMalQueryDownloadV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetMalQueryDownloadV1NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetMalQueryDownloadV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetMalQueryDownloadV1InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /malquery/entities/download-files/v1] GetMalQueryDownloadV1", response, response.Code())
	}
}

// NewGetMalQueryDownloadV1OK creates a GetMalQueryDownloadV1OK with default headers values
func NewGetMalQueryDownloadV1OK() *GetMalQueryDownloadV1OK {
	return &GetMalQueryDownloadV1OK{}
}

/* GetMalQueryDownloadV1OK describes a response with status code 200, with default header values.

The file content
*/
type GetMalQueryDownloadV1OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64
}

// IsSuccess returns true when this get mal query download v1 o k response has a 2xx status code
func (o *GetMalQueryDownloadV1OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get mal query download v1 o k response has a 3xx status code
func (o *GetMalQueryDownloadV1OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 o k response has a 4xx status code
func (o *GetMalQueryDownloadV1OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get mal query download v1 o k response has a 5xx status code
func (o *GetMalQueryDownloadV1OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get mal query download v1 o k response a status code equal to that given
func (o *GetMalQueryDownloadV1OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get mal query download v1 o k response
func (o *GetMalQueryDownloadV1OK) Code() int {
	return 200
}

func (o *GetMalQueryDownloadV1OK) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1OK ", 200)
}

func (o *GetMalQueryDownloadV1OK) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1OK ", 200)
}

func (o *GetMalQueryDownloadV1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	return nil
}

// NewGetMalQueryDownloadV1BadRequest creates a GetMalQueryDownloadV1BadRequest with default headers values
func NewGetMalQueryDownloadV1BadRequest() *GetMalQueryDownloadV1BadRequest {
	return &GetMalQueryDownloadV1BadRequest{}
}

/* GetMalQueryDownloadV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetMalQueryDownloadV1BadRequest struct {

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

// IsSuccess returns true when this get mal query download v1 bad request response has a 2xx status code
func (o *GetMalQueryDownloadV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get mal query download v1 bad request response has a 3xx status code
func (o *GetMalQueryDownloadV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 bad request response has a 4xx status code
func (o *GetMalQueryDownloadV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get mal query download v1 bad request response has a 5xx status code
func (o *GetMalQueryDownloadV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get mal query download v1 bad request response a status code equal to that given
func (o *GetMalQueryDownloadV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get mal query download v1 bad request response
func (o *GetMalQueryDownloadV1BadRequest) Code() int {
	return 400
}

func (o *GetMalQueryDownloadV1BadRequest) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1BadRequest  %+v", 400, o.Payload)
}

func (o *GetMalQueryDownloadV1BadRequest) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1BadRequest  %+v", 400, o.Payload)
}

func (o *GetMalQueryDownloadV1BadRequest) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetMalQueryDownloadV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMalQueryDownloadV1Unauthorized creates a GetMalQueryDownloadV1Unauthorized with default headers values
func NewGetMalQueryDownloadV1Unauthorized() *GetMalQueryDownloadV1Unauthorized {
	return &GetMalQueryDownloadV1Unauthorized{}
}

/* GetMalQueryDownloadV1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetMalQueryDownloadV1Unauthorized struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this get mal query download v1 unauthorized response has a 2xx status code
func (o *GetMalQueryDownloadV1Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get mal query download v1 unauthorized response has a 3xx status code
func (o *GetMalQueryDownloadV1Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 unauthorized response has a 4xx status code
func (o *GetMalQueryDownloadV1Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get mal query download v1 unauthorized response has a 5xx status code
func (o *GetMalQueryDownloadV1Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get mal query download v1 unauthorized response a status code equal to that given
func (o *GetMalQueryDownloadV1Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get mal query download v1 unauthorized response
func (o *GetMalQueryDownloadV1Unauthorized) Code() int {
	return 401
}

func (o *GetMalQueryDownloadV1Unauthorized) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1Unauthorized  %+v", 401, o.Payload)
}

func (o *GetMalQueryDownloadV1Unauthorized) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1Unauthorized  %+v", 401, o.Payload)
}

func (o *GetMalQueryDownloadV1Unauthorized) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *GetMalQueryDownloadV1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMalQueryDownloadV1Forbidden creates a GetMalQueryDownloadV1Forbidden with default headers values
func NewGetMalQueryDownloadV1Forbidden() *GetMalQueryDownloadV1Forbidden {
	return &GetMalQueryDownloadV1Forbidden{}
}

/* GetMalQueryDownloadV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetMalQueryDownloadV1Forbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this get mal query download v1 forbidden response has a 2xx status code
func (o *GetMalQueryDownloadV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get mal query download v1 forbidden response has a 3xx status code
func (o *GetMalQueryDownloadV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 forbidden response has a 4xx status code
func (o *GetMalQueryDownloadV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get mal query download v1 forbidden response has a 5xx status code
func (o *GetMalQueryDownloadV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get mal query download v1 forbidden response a status code equal to that given
func (o *GetMalQueryDownloadV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get mal query download v1 forbidden response
func (o *GetMalQueryDownloadV1Forbidden) Code() int {
	return 403
}

func (o *GetMalQueryDownloadV1Forbidden) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1Forbidden  %+v", 403, o.Payload)
}

func (o *GetMalQueryDownloadV1Forbidden) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1Forbidden  %+v", 403, o.Payload)
}

func (o *GetMalQueryDownloadV1Forbidden) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *GetMalQueryDownloadV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMalQueryDownloadV1NotFound creates a GetMalQueryDownloadV1NotFound with default headers values
func NewGetMalQueryDownloadV1NotFound() *GetMalQueryDownloadV1NotFound {
	return &GetMalQueryDownloadV1NotFound{}
}

/* GetMalQueryDownloadV1NotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetMalQueryDownloadV1NotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaErrorsOnly
}

// IsSuccess returns true when this get mal query download v1 not found response has a 2xx status code
func (o *GetMalQueryDownloadV1NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get mal query download v1 not found response has a 3xx status code
func (o *GetMalQueryDownloadV1NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 not found response has a 4xx status code
func (o *GetMalQueryDownloadV1NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get mal query download v1 not found response has a 5xx status code
func (o *GetMalQueryDownloadV1NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get mal query download v1 not found response a status code equal to that given
func (o *GetMalQueryDownloadV1NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get mal query download v1 not found response
func (o *GetMalQueryDownloadV1NotFound) Code() int {
	return 404
}

func (o *GetMalQueryDownloadV1NotFound) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1NotFound  %+v", 404, o.Payload)
}

func (o *GetMalQueryDownloadV1NotFound) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1NotFound  %+v", 404, o.Payload)
}

func (o *GetMalQueryDownloadV1NotFound) GetPayload() *models.MsaErrorsOnly {
	return o.Payload
}

func (o *GetMalQueryDownloadV1NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaErrorsOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMalQueryDownloadV1TooManyRequests creates a GetMalQueryDownloadV1TooManyRequests with default headers values
func NewGetMalQueryDownloadV1TooManyRequests() *GetMalQueryDownloadV1TooManyRequests {
	return &GetMalQueryDownloadV1TooManyRequests{}
}

/* GetMalQueryDownloadV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetMalQueryDownloadV1TooManyRequests struct {

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

// IsSuccess returns true when this get mal query download v1 too many requests response has a 2xx status code
func (o *GetMalQueryDownloadV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get mal query download v1 too many requests response has a 3xx status code
func (o *GetMalQueryDownloadV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 too many requests response has a 4xx status code
func (o *GetMalQueryDownloadV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get mal query download v1 too many requests response has a 5xx status code
func (o *GetMalQueryDownloadV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get mal query download v1 too many requests response a status code equal to that given
func (o *GetMalQueryDownloadV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get mal query download v1 too many requests response
func (o *GetMalQueryDownloadV1TooManyRequests) Code() int {
	return 429
}

func (o *GetMalQueryDownloadV1TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetMalQueryDownloadV1TooManyRequests) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetMalQueryDownloadV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetMalQueryDownloadV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetMalQueryDownloadV1InternalServerError creates a GetMalQueryDownloadV1InternalServerError with default headers values
func NewGetMalQueryDownloadV1InternalServerError() *GetMalQueryDownloadV1InternalServerError {
	return &GetMalQueryDownloadV1InternalServerError{}
}

/* GetMalQueryDownloadV1InternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetMalQueryDownloadV1InternalServerError struct {

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

// IsSuccess returns true when this get mal query download v1 internal server error response has a 2xx status code
func (o *GetMalQueryDownloadV1InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get mal query download v1 internal server error response has a 3xx status code
func (o *GetMalQueryDownloadV1InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get mal query download v1 internal server error response has a 4xx status code
func (o *GetMalQueryDownloadV1InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get mal query download v1 internal server error response has a 5xx status code
func (o *GetMalQueryDownloadV1InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get mal query download v1 internal server error response a status code equal to that given
func (o *GetMalQueryDownloadV1InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get mal query download v1 internal server error response
func (o *GetMalQueryDownloadV1InternalServerError) Code() int {
	return 500
}

func (o *GetMalQueryDownloadV1InternalServerError) Error() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1InternalServerError  %+v", 500, o.Payload)
}

func (o *GetMalQueryDownloadV1InternalServerError) String() string {
	return fmt.Sprintf("[GET /malquery/entities/download-files/v1][%d] getMalQueryDownloadV1InternalServerError  %+v", 500, o.Payload)
}

func (o *GetMalQueryDownloadV1InternalServerError) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetMalQueryDownloadV1InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
