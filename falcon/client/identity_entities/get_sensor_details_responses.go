// Code generated by go-swagger; DO NOT EDIT.

package identity_entities

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

// GetSensorDetailsReader is a Reader for the GetSensorDetails structure.
type GetSensorDetailsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetSensorDetailsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetSensorDetailsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewGetSensorDetailsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetSensorDetailsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /identity-protection/entities/devices/GET/v1] GetSensorDetails", response, response.Code())
	}
}

// NewGetSensorDetailsOK creates a GetSensorDetailsOK with default headers values
func NewGetSensorDetailsOK() *GetSensorDetailsOK {
	return &GetSensorDetailsOK{}
}

/* GetSensorDetailsOK describes a response with status code 200, with default header values.

OK
*/
type GetSensorDetailsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APISensorDetailsResponseSwagger
}

// IsSuccess returns true when this get sensor details o k response has a 2xx status code
func (o *GetSensorDetailsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get sensor details o k response has a 3xx status code
func (o *GetSensorDetailsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get sensor details o k response has a 4xx status code
func (o *GetSensorDetailsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get sensor details o k response has a 5xx status code
func (o *GetSensorDetailsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get sensor details o k response a status code equal to that given
func (o *GetSensorDetailsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get sensor details o k response
func (o *GetSensorDetailsOK) Code() int {
	return 200
}

func (o *GetSensorDetailsOK) Error() string {
	return fmt.Sprintf("[POST /identity-protection/entities/devices/GET/v1][%d] getSensorDetailsOK  %+v", 200, o.Payload)
}

func (o *GetSensorDetailsOK) String() string {
	return fmt.Sprintf("[POST /identity-protection/entities/devices/GET/v1][%d] getSensorDetailsOK  %+v", 200, o.Payload)
}

func (o *GetSensorDetailsOK) GetPayload() *models.APISensorDetailsResponseSwagger {
	return o.Payload
}

func (o *GetSensorDetailsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.APISensorDetailsResponseSwagger)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSensorDetailsForbidden creates a GetSensorDetailsForbidden with default headers values
func NewGetSensorDetailsForbidden() *GetSensorDetailsForbidden {
	return &GetSensorDetailsForbidden{}
}

/* GetSensorDetailsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetSensorDetailsForbidden struct {

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

// IsSuccess returns true when this get sensor details forbidden response has a 2xx status code
func (o *GetSensorDetailsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get sensor details forbidden response has a 3xx status code
func (o *GetSensorDetailsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get sensor details forbidden response has a 4xx status code
func (o *GetSensorDetailsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get sensor details forbidden response has a 5xx status code
func (o *GetSensorDetailsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get sensor details forbidden response a status code equal to that given
func (o *GetSensorDetailsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get sensor details forbidden response
func (o *GetSensorDetailsForbidden) Code() int {
	return 403
}

func (o *GetSensorDetailsForbidden) Error() string {
	return fmt.Sprintf("[POST /identity-protection/entities/devices/GET/v1][%d] getSensorDetailsForbidden  %+v", 403, o.Payload)
}

func (o *GetSensorDetailsForbidden) String() string {
	return fmt.Sprintf("[POST /identity-protection/entities/devices/GET/v1][%d] getSensorDetailsForbidden  %+v", 403, o.Payload)
}

func (o *GetSensorDetailsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetSensorDetailsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetSensorDetailsTooManyRequests creates a GetSensorDetailsTooManyRequests with default headers values
func NewGetSensorDetailsTooManyRequests() *GetSensorDetailsTooManyRequests {
	return &GetSensorDetailsTooManyRequests{}
}

/* GetSensorDetailsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetSensorDetailsTooManyRequests struct {

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

// IsSuccess returns true when this get sensor details too many requests response has a 2xx status code
func (o *GetSensorDetailsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get sensor details too many requests response has a 3xx status code
func (o *GetSensorDetailsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get sensor details too many requests response has a 4xx status code
func (o *GetSensorDetailsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get sensor details too many requests response has a 5xx status code
func (o *GetSensorDetailsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get sensor details too many requests response a status code equal to that given
func (o *GetSensorDetailsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get sensor details too many requests response
func (o *GetSensorDetailsTooManyRequests) Code() int {
	return 429
}

func (o *GetSensorDetailsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /identity-protection/entities/devices/GET/v1][%d] getSensorDetailsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetSensorDetailsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /identity-protection/entities/devices/GET/v1][%d] getSensorDetailsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetSensorDetailsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *GetSensorDetailsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
