// Code generated by go-swagger; DO NOT EDIT.

package ioc

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

// IndicatorCreateV1Reader is a Reader for the IndicatorCreateV1 structure.
type IndicatorCreateV1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndicatorCreateV1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewIndicatorCreateV1Created()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewIndicatorCreateV1BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewIndicatorCreateV1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewIndicatorCreateV1TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /iocs/entities/indicators/v1] indicator.create.v1", response, response.Code())
	}
}

// NewIndicatorCreateV1Created creates a IndicatorCreateV1Created with default headers values
func NewIndicatorCreateV1Created() *IndicatorCreateV1Created {
	return &IndicatorCreateV1Created{}
}

/*
IndicatorCreateV1Created describes a response with status code 201, with default header values.

Created
*/
type IndicatorCreateV1Created struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIIndicatorRespV1
}

// IsSuccess returns true when this indicator create v1 created response has a 2xx status code
func (o *IndicatorCreateV1Created) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indicator create v1 created response has a 3xx status code
func (o *IndicatorCreateV1Created) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator create v1 created response has a 4xx status code
func (o *IndicatorCreateV1Created) IsClientError() bool {
	return false
}

// IsServerError returns true when this indicator create v1 created response has a 5xx status code
func (o *IndicatorCreateV1Created) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator create v1 created response a status code equal to that given
func (o *IndicatorCreateV1Created) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the indicator create v1 created response
func (o *IndicatorCreateV1Created) Code() int {
	return 201
}

func (o *IndicatorCreateV1Created) Error() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1Created  %+v", 201, o.Payload)
}

func (o *IndicatorCreateV1Created) String() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1Created  %+v", 201, o.Payload)
}

func (o *IndicatorCreateV1Created) GetPayload() *models.APIIndicatorRespV1 {
	return o.Payload
}

func (o *IndicatorCreateV1Created) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APIIndicatorRespV1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndicatorCreateV1BadRequest creates a IndicatorCreateV1BadRequest with default headers values
func NewIndicatorCreateV1BadRequest() *IndicatorCreateV1BadRequest {
	return &IndicatorCreateV1BadRequest{}
}

/*
IndicatorCreateV1BadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type IndicatorCreateV1BadRequest struct {

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

// IsSuccess returns true when this indicator create v1 bad request response has a 2xx status code
func (o *IndicatorCreateV1BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator create v1 bad request response has a 3xx status code
func (o *IndicatorCreateV1BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator create v1 bad request response has a 4xx status code
func (o *IndicatorCreateV1BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator create v1 bad request response has a 5xx status code
func (o *IndicatorCreateV1BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator create v1 bad request response a status code equal to that given
func (o *IndicatorCreateV1BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the indicator create v1 bad request response
func (o *IndicatorCreateV1BadRequest) Code() int {
	return 400
}

func (o *IndicatorCreateV1BadRequest) Error() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1BadRequest  %+v", 400, o.Payload)
}

func (o *IndicatorCreateV1BadRequest) String() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1BadRequest  %+v", 400, o.Payload)
}

func (o *IndicatorCreateV1BadRequest) GetPayload() *models.MsaspecResponseFields {
	return o.Payload
}

func (o *IndicatorCreateV1BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorCreateV1Forbidden creates a IndicatorCreateV1Forbidden with default headers values
func NewIndicatorCreateV1Forbidden() *IndicatorCreateV1Forbidden {
	return &IndicatorCreateV1Forbidden{}
}

/*
IndicatorCreateV1Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type IndicatorCreateV1Forbidden struct {

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

// IsSuccess returns true when this indicator create v1 forbidden response has a 2xx status code
func (o *IndicatorCreateV1Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator create v1 forbidden response has a 3xx status code
func (o *IndicatorCreateV1Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator create v1 forbidden response has a 4xx status code
func (o *IndicatorCreateV1Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator create v1 forbidden response has a 5xx status code
func (o *IndicatorCreateV1Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator create v1 forbidden response a status code equal to that given
func (o *IndicatorCreateV1Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the indicator create v1 forbidden response
func (o *IndicatorCreateV1Forbidden) Code() int {
	return 403
}

func (o *IndicatorCreateV1Forbidden) Error() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1Forbidden  %+v", 403, o.Payload)
}

func (o *IndicatorCreateV1Forbidden) String() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1Forbidden  %+v", 403, o.Payload)
}

func (o *IndicatorCreateV1Forbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorCreateV1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewIndicatorCreateV1TooManyRequests creates a IndicatorCreateV1TooManyRequests with default headers values
func NewIndicatorCreateV1TooManyRequests() *IndicatorCreateV1TooManyRequests {
	return &IndicatorCreateV1TooManyRequests{}
}

/*
IndicatorCreateV1TooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type IndicatorCreateV1TooManyRequests struct {

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

// IsSuccess returns true when this indicator create v1 too many requests response has a 2xx status code
func (o *IndicatorCreateV1TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this indicator create v1 too many requests response has a 3xx status code
func (o *IndicatorCreateV1TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indicator create v1 too many requests response has a 4xx status code
func (o *IndicatorCreateV1TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this indicator create v1 too many requests response has a 5xx status code
func (o *IndicatorCreateV1TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this indicator create v1 too many requests response a status code equal to that given
func (o *IndicatorCreateV1TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the indicator create v1 too many requests response
func (o *IndicatorCreateV1TooManyRequests) Code() int {
	return 429
}

func (o *IndicatorCreateV1TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IndicatorCreateV1TooManyRequests) String() string {
	return fmt.Sprintf("[POST /iocs/entities/indicators/v1][%d] indicatorCreateV1TooManyRequests  %+v", 429, o.Payload)
}

func (o *IndicatorCreateV1TooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *IndicatorCreateV1TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
