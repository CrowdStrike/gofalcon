// Code generated by go-swagger; DO NOT EDIT.

package sensor_download

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

// GetCombinedSensorInstallersByQueryV2Reader is a Reader for the GetCombinedSensorInstallersByQueryV2 structure.
type GetCombinedSensorInstallersByQueryV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCombinedSensorInstallersByQueryV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetCombinedSensorInstallersByQueryV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetCombinedSensorInstallersByQueryV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetCombinedSensorInstallersByQueryV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetCombinedSensorInstallersByQueryV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /sensors/combined/installers/v2] GetCombinedSensorInstallersByQueryV2", response, response.Code())
	}
}

// NewGetCombinedSensorInstallersByQueryV2OK creates a GetCombinedSensorInstallersByQueryV2OK with default headers values
func NewGetCombinedSensorInstallersByQueryV2OK() *GetCombinedSensorInstallersByQueryV2OK {
	return &GetCombinedSensorInstallersByQueryV2OK{}
}

/*
GetCombinedSensorInstallersByQueryV2OK describes a response with status code 200, with default header values.

OK
*/
type GetCombinedSensorInstallersByQueryV2OK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DomainSensorInstallersV2
}

// IsSuccess returns true when this get combined sensor installers by query v2 o k response has a 2xx status code
func (o *GetCombinedSensorInstallersByQueryV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get combined sensor installers by query v2 o k response has a 3xx status code
func (o *GetCombinedSensorInstallersByQueryV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get combined sensor installers by query v2 o k response has a 4xx status code
func (o *GetCombinedSensorInstallersByQueryV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get combined sensor installers by query v2 o k response has a 5xx status code
func (o *GetCombinedSensorInstallersByQueryV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get combined sensor installers by query v2 o k response a status code equal to that given
func (o *GetCombinedSensorInstallersByQueryV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get combined sensor installers by query v2 o k response
func (o *GetCombinedSensorInstallersByQueryV2OK) Code() int {
	return 200
}

func (o *GetCombinedSensorInstallersByQueryV2OK) Error() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2OK  %+v", 200, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2OK) String() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2OK  %+v", 200, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2OK) GetPayload() *models.DomainSensorInstallersV2 {
	return o.Payload
}

func (o *GetCombinedSensorInstallersByQueryV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DomainSensorInstallersV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCombinedSensorInstallersByQueryV2BadRequest creates a GetCombinedSensorInstallersByQueryV2BadRequest with default headers values
func NewGetCombinedSensorInstallersByQueryV2BadRequest() *GetCombinedSensorInstallersByQueryV2BadRequest {
	return &GetCombinedSensorInstallersByQueryV2BadRequest{}
}

/*
GetCombinedSensorInstallersByQueryV2BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetCombinedSensorInstallersByQueryV2BadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaspecQueryResponse
}

// IsSuccess returns true when this get combined sensor installers by query v2 bad request response has a 2xx status code
func (o *GetCombinedSensorInstallersByQueryV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get combined sensor installers by query v2 bad request response has a 3xx status code
func (o *GetCombinedSensorInstallersByQueryV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get combined sensor installers by query v2 bad request response has a 4xx status code
func (o *GetCombinedSensorInstallersByQueryV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get combined sensor installers by query v2 bad request response has a 5xx status code
func (o *GetCombinedSensorInstallersByQueryV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get combined sensor installers by query v2 bad request response a status code equal to that given
func (o *GetCombinedSensorInstallersByQueryV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get combined sensor installers by query v2 bad request response
func (o *GetCombinedSensorInstallersByQueryV2BadRequest) Code() int {
	return 400
}

func (o *GetCombinedSensorInstallersByQueryV2BadRequest) Error() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2BadRequest  %+v", 400, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2BadRequest) String() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2BadRequest  %+v", 400, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2BadRequest) GetPayload() *models.MsaspecQueryResponse {
	return o.Payload
}

func (o *GetCombinedSensorInstallersByQueryV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaspecQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCombinedSensorInstallersByQueryV2Forbidden creates a GetCombinedSensorInstallersByQueryV2Forbidden with default headers values
func NewGetCombinedSensorInstallersByQueryV2Forbidden() *GetCombinedSensorInstallersByQueryV2Forbidden {
	return &GetCombinedSensorInstallersByQueryV2Forbidden{}
}

/*
GetCombinedSensorInstallersByQueryV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetCombinedSensorInstallersByQueryV2Forbidden struct {

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

// IsSuccess returns true when this get combined sensor installers by query v2 forbidden response has a 2xx status code
func (o *GetCombinedSensorInstallersByQueryV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get combined sensor installers by query v2 forbidden response has a 3xx status code
func (o *GetCombinedSensorInstallersByQueryV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get combined sensor installers by query v2 forbidden response has a 4xx status code
func (o *GetCombinedSensorInstallersByQueryV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get combined sensor installers by query v2 forbidden response has a 5xx status code
func (o *GetCombinedSensorInstallersByQueryV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get combined sensor installers by query v2 forbidden response a status code equal to that given
func (o *GetCombinedSensorInstallersByQueryV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get combined sensor installers by query v2 forbidden response
func (o *GetCombinedSensorInstallersByQueryV2Forbidden) Code() int {
	return 403
}

func (o *GetCombinedSensorInstallersByQueryV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2Forbidden) String() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetCombinedSensorInstallersByQueryV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetCombinedSensorInstallersByQueryV2TooManyRequests creates a GetCombinedSensorInstallersByQueryV2TooManyRequests with default headers values
func NewGetCombinedSensorInstallersByQueryV2TooManyRequests() *GetCombinedSensorInstallersByQueryV2TooManyRequests {
	return &GetCombinedSensorInstallersByQueryV2TooManyRequests{}
}

/*
GetCombinedSensorInstallersByQueryV2TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetCombinedSensorInstallersByQueryV2TooManyRequests struct {

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

// IsSuccess returns true when this get combined sensor installers by query v2 too many requests response has a 2xx status code
func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get combined sensor installers by query v2 too many requests response has a 3xx status code
func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get combined sensor installers by query v2 too many requests response has a 4xx status code
func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get combined sensor installers by query v2 too many requests response has a 5xx status code
func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get combined sensor installers by query v2 too many requests response a status code equal to that given
func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get combined sensor installers by query v2 too many requests response
func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) Code() int {
	return 429
}

func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /sensors/combined/installers/v2][%d] getCombinedSensorInstallersByQueryV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetCombinedSensorInstallersByQueryV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
