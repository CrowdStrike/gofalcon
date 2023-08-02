// Code generated by go-swagger; DO NOT EDIT.

package quick_scan

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

// GetScansReader is a Reader for the GetScans structure.
type GetScansReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetScansReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetScansOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetScansBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetScansForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetScansNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetScansTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetScansInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /scanner/entities/scans/v1] GetScans", response, response.Code())
	}
}

// NewGetScansOK creates a GetScansOK with default headers values
func NewGetScansOK() *GetScansOK {
	return &GetScansOK{}
}

/*
GetScansOK describes a response with status code 200, with default header values.

OK
*/
type GetScansOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiScanV1Response
}

// IsSuccess returns true when this get scans o k response has a 2xx status code
func (o *GetScansOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get scans o k response has a 3xx status code
func (o *GetScansOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans o k response has a 4xx status code
func (o *GetScansOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get scans o k response has a 5xx status code
func (o *GetScansOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans o k response a status code equal to that given
func (o *GetScansOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get scans o k response
func (o *GetScansOK) Code() int {
	return 200
}

func (o *GetScansOK) Error() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansOK  %+v", 200, o.Payload)
}

func (o *GetScansOK) String() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansOK  %+v", 200, o.Payload)
}

func (o *GetScansOK) GetPayload() *models.MlscannerapiScanV1Response {
	return o.Payload
}

func (o *GetScansOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiScanV1Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScansBadRequest creates a GetScansBadRequest with default headers values
func NewGetScansBadRequest() *GetScansBadRequest {
	return &GetScansBadRequest{}
}

/*
GetScansBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetScansBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiScanV1Response
}

// IsSuccess returns true when this get scans bad request response has a 2xx status code
func (o *GetScansBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans bad request response has a 3xx status code
func (o *GetScansBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans bad request response has a 4xx status code
func (o *GetScansBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans bad request response has a 5xx status code
func (o *GetScansBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans bad request response a status code equal to that given
func (o *GetScansBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get scans bad request response
func (o *GetScansBadRequest) Code() int {
	return 400
}

func (o *GetScansBadRequest) Error() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansBadRequest  %+v", 400, o.Payload)
}

func (o *GetScansBadRequest) String() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansBadRequest  %+v", 400, o.Payload)
}

func (o *GetScansBadRequest) GetPayload() *models.MlscannerapiScanV1Response {
	return o.Payload
}

func (o *GetScansBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiScanV1Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScansForbidden creates a GetScansForbidden with default headers values
func NewGetScansForbidden() *GetScansForbidden {
	return &GetScansForbidden{}
}

/*
GetScansForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetScansForbidden struct {

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

// IsSuccess returns true when this get scans forbidden response has a 2xx status code
func (o *GetScansForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans forbidden response has a 3xx status code
func (o *GetScansForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans forbidden response has a 4xx status code
func (o *GetScansForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans forbidden response has a 5xx status code
func (o *GetScansForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans forbidden response a status code equal to that given
func (o *GetScansForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get scans forbidden response
func (o *GetScansForbidden) Code() int {
	return 403
}

func (o *GetScansForbidden) Error() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansForbidden  %+v", 403, o.Payload)
}

func (o *GetScansForbidden) String() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansForbidden  %+v", 403, o.Payload)
}

func (o *GetScansForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScansForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScansNotFound creates a GetScansNotFound with default headers values
func NewGetScansNotFound() *GetScansNotFound {
	return &GetScansNotFound{}
}

/*
GetScansNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetScansNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiScanV1Response
}

// IsSuccess returns true when this get scans not found response has a 2xx status code
func (o *GetScansNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans not found response has a 3xx status code
func (o *GetScansNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans not found response has a 4xx status code
func (o *GetScansNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans not found response has a 5xx status code
func (o *GetScansNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans not found response a status code equal to that given
func (o *GetScansNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get scans not found response
func (o *GetScansNotFound) Code() int {
	return 404
}

func (o *GetScansNotFound) Error() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansNotFound  %+v", 404, o.Payload)
}

func (o *GetScansNotFound) String() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansNotFound  %+v", 404, o.Payload)
}

func (o *GetScansNotFound) GetPayload() *models.MlscannerapiScanV1Response {
	return o.Payload
}

func (o *GetScansNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiScanV1Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScansTooManyRequests creates a GetScansTooManyRequests with default headers values
func NewGetScansTooManyRequests() *GetScansTooManyRequests {
	return &GetScansTooManyRequests{}
}

/*
GetScansTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetScansTooManyRequests struct {

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

// IsSuccess returns true when this get scans too many requests response has a 2xx status code
func (o *GetScansTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans too many requests response has a 3xx status code
func (o *GetScansTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans too many requests response has a 4xx status code
func (o *GetScansTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scans too many requests response has a 5xx status code
func (o *GetScansTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get scans too many requests response a status code equal to that given
func (o *GetScansTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get scans too many requests response
func (o *GetScansTooManyRequests) Code() int {
	return 429
}

func (o *GetScansTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScansTooManyRequests) String() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScansTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScansTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScansInternalServerError creates a GetScansInternalServerError with default headers values
func NewGetScansInternalServerError() *GetScansInternalServerError {
	return &GetScansInternalServerError{}
}

/*
GetScansInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetScansInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MlscannerapiScanV1Response
}

// IsSuccess returns true when this get scans internal server error response has a 2xx status code
func (o *GetScansInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scans internal server error response has a 3xx status code
func (o *GetScansInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scans internal server error response has a 4xx status code
func (o *GetScansInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get scans internal server error response has a 5xx status code
func (o *GetScansInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get scans internal server error response a status code equal to that given
func (o *GetScansInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get scans internal server error response
func (o *GetScansInternalServerError) Code() int {
	return 500
}

func (o *GetScansInternalServerError) Error() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansInternalServerError  %+v", 500, o.Payload)
}

func (o *GetScansInternalServerError) String() string {
	return fmt.Sprintf("[GET /scanner/entities/scans/v1][%d] getScansInternalServerError  %+v", 500, o.Payload)
}

func (o *GetScansInternalServerError) GetPayload() *models.MlscannerapiScanV1Response {
	return o.Payload
}

func (o *GetScansInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MlscannerapiScanV1Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
