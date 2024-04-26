// Code generated by go-swagger; DO NOT EDIT.

package cloud_snapshots

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

// GetScanReportReader is a Reader for the GetScanReport structure.
type GetScanReportReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetScanReportReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetScanReportOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetScanReportBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetScanReportForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetScanReportNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetScanReportTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetScanReportInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /snapshots/entities/scanreports/v1] GetScanReport", response, response.Code())
	}
}

// NewGetScanReportOK creates a GetScanReportOK with default headers values
func NewGetScanReportOK() *GetScanReportOK {
	return &GetScanReportOK{}
}

/*
GetScanReportOK describes a response with status code 200, with default header values.

OK
*/
type GetScanReportOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.ScanreportsEntitiesResponse
}

// IsSuccess returns true when this get scan report o k response has a 2xx status code
func (o *GetScanReportOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get scan report o k response has a 3xx status code
func (o *GetScanReportOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scan report o k response has a 4xx status code
func (o *GetScanReportOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get scan report o k response has a 5xx status code
func (o *GetScanReportOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get scan report o k response a status code equal to that given
func (o *GetScanReportOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get scan report o k response
func (o *GetScanReportOK) Code() int {
	return 200
}

func (o *GetScanReportOK) Error() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportOK  %+v", 200, o.Payload)
}

func (o *GetScanReportOK) String() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportOK  %+v", 200, o.Payload)
}

func (o *GetScanReportOK) GetPayload() *models.ScanreportsEntitiesResponse {
	return o.Payload
}

func (o *GetScanReportOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.ScanreportsEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScanReportBadRequest creates a GetScanReportBadRequest with default headers values
func NewGetScanReportBadRequest() *GetScanReportBadRequest {
	return &GetScanReportBadRequest{}
}

/*
GetScanReportBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetScanReportBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this get scan report bad request response has a 2xx status code
func (o *GetScanReportBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scan report bad request response has a 3xx status code
func (o *GetScanReportBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scan report bad request response has a 4xx status code
func (o *GetScanReportBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scan report bad request response has a 5xx status code
func (o *GetScanReportBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get scan report bad request response a status code equal to that given
func (o *GetScanReportBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get scan report bad request response
func (o *GetScanReportBadRequest) Code() int {
	return 400
}

func (o *GetScanReportBadRequest) Error() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportBadRequest  %+v", 400, o.Payload)
}

func (o *GetScanReportBadRequest) String() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportBadRequest  %+v", 400, o.Payload)
}

func (o *GetScanReportBadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetScanReportBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScanReportForbidden creates a GetScanReportForbidden with default headers values
func NewGetScanReportForbidden() *GetScanReportForbidden {
	return &GetScanReportForbidden{}
}

/*
GetScanReportForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetScanReportForbidden struct {

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

// IsSuccess returns true when this get scan report forbidden response has a 2xx status code
func (o *GetScanReportForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scan report forbidden response has a 3xx status code
func (o *GetScanReportForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scan report forbidden response has a 4xx status code
func (o *GetScanReportForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scan report forbidden response has a 5xx status code
func (o *GetScanReportForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get scan report forbidden response a status code equal to that given
func (o *GetScanReportForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get scan report forbidden response
func (o *GetScanReportForbidden) Code() int {
	return 403
}

func (o *GetScanReportForbidden) Error() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportForbidden  %+v", 403, o.Payload)
}

func (o *GetScanReportForbidden) String() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportForbidden  %+v", 403, o.Payload)
}

func (o *GetScanReportForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScanReportForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScanReportNotFound creates a GetScanReportNotFound with default headers values
func NewGetScanReportNotFound() *GetScanReportNotFound {
	return &GetScanReportNotFound{}
}

/*
GetScanReportNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetScanReportNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this get scan report not found response has a 2xx status code
func (o *GetScanReportNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scan report not found response has a 3xx status code
func (o *GetScanReportNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scan report not found response has a 4xx status code
func (o *GetScanReportNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scan report not found response has a 5xx status code
func (o *GetScanReportNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get scan report not found response a status code equal to that given
func (o *GetScanReportNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get scan report not found response
func (o *GetScanReportNotFound) Code() int {
	return 404
}

func (o *GetScanReportNotFound) Error() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportNotFound  %+v", 404, o.Payload)
}

func (o *GetScanReportNotFound) String() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportNotFound  %+v", 404, o.Payload)
}

func (o *GetScanReportNotFound) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetScanReportNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScanReportTooManyRequests creates a GetScanReportTooManyRequests with default headers values
func NewGetScanReportTooManyRequests() *GetScanReportTooManyRequests {
	return &GetScanReportTooManyRequests{}
}

/*
GetScanReportTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetScanReportTooManyRequests struct {

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

// IsSuccess returns true when this get scan report too many requests response has a 2xx status code
func (o *GetScanReportTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scan report too many requests response has a 3xx status code
func (o *GetScanReportTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scan report too many requests response has a 4xx status code
func (o *GetScanReportTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get scan report too many requests response has a 5xx status code
func (o *GetScanReportTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get scan report too many requests response a status code equal to that given
func (o *GetScanReportTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get scan report too many requests response
func (o *GetScanReportTooManyRequests) Code() int {
	return 429
}

func (o *GetScanReportTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScanReportTooManyRequests) String() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScanReportTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetScanReportTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetScanReportInternalServerError creates a GetScanReportInternalServerError with default headers values
func NewGetScanReportInternalServerError() *GetScanReportInternalServerError {
	return &GetScanReportInternalServerError{}
}

/*
GetScanReportInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetScanReportInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecResponseFields
}

// IsSuccess returns true when this get scan report internal server error response has a 2xx status code
func (o *GetScanReportInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get scan report internal server error response has a 3xx status code
func (o *GetScanReportInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get scan report internal server error response has a 4xx status code
func (o *GetScanReportInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get scan report internal server error response has a 5xx status code
func (o *GetScanReportInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get scan report internal server error response a status code equal to that given
func (o *GetScanReportInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get scan report internal server error response
func (o *GetScanReportInternalServerError) Code() int {
	return 500
}

func (o *GetScanReportInternalServerError) Error() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportInternalServerError  %+v", 500, o.Payload)
}

func (o *GetScanReportInternalServerError) String() string {
	return fmt.Sprintf("[GET /snapshots/entities/scanreports/v1][%d] getScanReportInternalServerError  %+v", 500, o.Payload)
}

func (o *GetScanReportInternalServerError) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *GetScanReportInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecResponseFields)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
