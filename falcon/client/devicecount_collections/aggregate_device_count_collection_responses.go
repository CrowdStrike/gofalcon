// Code generated by go-swagger; DO NOT EDIT.

package devicecount_collections

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

// AggregateDeviceCountCollectionReader is a Reader for the AggregateDeviceCountCollection structure.
type AggregateDeviceCountCollectionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AggregateDeviceCountCollectionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAggregateDeviceCountCollectionOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewAggregateDeviceCountCollectionForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAggregateDeviceCountCollectionTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewAggregateDeviceCountCollectionDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAggregateDeviceCountCollectionOK creates a AggregateDeviceCountCollectionOK with default headers values
func NewAggregateDeviceCountCollectionOK() *AggregateDeviceCountCollectionOK {
	return &AggregateDeviceCountCollectionOK{}
}

/* AggregateDeviceCountCollectionOK describes a response with status code 200, with default header values.

OK
*/
type AggregateDeviceCountCollectionOK struct {

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaAggregatesResponse
}

func (o *AggregateDeviceCountCollectionOK) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/devicecount-collections/GET/v1][%d] aggregateDeviceCountCollectionOK  %+v", 200, o.Payload)
}
func (o *AggregateDeviceCountCollectionOK) GetPayload() *models.MsaAggregatesResponse {
	return o.Payload
}

func (o *AggregateDeviceCountCollectionOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.MsaAggregatesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAggregateDeviceCountCollectionForbidden creates a AggregateDeviceCountCollectionForbidden with default headers values
func NewAggregateDeviceCountCollectionForbidden() *AggregateDeviceCountCollectionForbidden {
	return &AggregateDeviceCountCollectionForbidden{}
}

/* AggregateDeviceCountCollectionForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AggregateDeviceCountCollectionForbidden struct {

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaReplyMetaOnly
}

func (o *AggregateDeviceCountCollectionForbidden) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/devicecount-collections/GET/v1][%d] aggregateDeviceCountCollectionForbidden  %+v", 403, o.Payload)
}
func (o *AggregateDeviceCountCollectionForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateDeviceCountCollectionForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateDeviceCountCollectionTooManyRequests creates a AggregateDeviceCountCollectionTooManyRequests with default headers values
func NewAggregateDeviceCountCollectionTooManyRequests() *AggregateDeviceCountCollectionTooManyRequests {
	return &AggregateDeviceCountCollectionTooManyRequests{}
}

/* AggregateDeviceCountCollectionTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type AggregateDeviceCountCollectionTooManyRequests struct {

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

func (o *AggregateDeviceCountCollectionTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/devicecount-collections/GET/v1][%d] aggregateDeviceCountCollectionTooManyRequests  %+v", 429, o.Payload)
}
func (o *AggregateDeviceCountCollectionTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *AggregateDeviceCountCollectionTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewAggregateDeviceCountCollectionDefault creates a AggregateDeviceCountCollectionDefault with default headers values
func NewAggregateDeviceCountCollectionDefault(code int) *AggregateDeviceCountCollectionDefault {
	return &AggregateDeviceCountCollectionDefault{
		_statusCode: code,
	}
}

/* AggregateDeviceCountCollectionDefault describes a response with status code -1, with default header values.

OK
*/
type AggregateDeviceCountCollectionDefault struct {
	_statusCode int

	Payload *models.MsaAggregatesResponse
}

// Code gets the status code for the aggregate device count collection default response
func (o *AggregateDeviceCountCollectionDefault) Code() int {
	return o._statusCode
}

func (o *AggregateDeviceCountCollectionDefault) Error() string {
	return fmt.Sprintf("[POST /falcon-complete-dashboards/aggregates/devicecount-collections/GET/v1][%d] AggregateDeviceCountCollection default  %+v", o._statusCode, o.Payload)
}
func (o *AggregateDeviceCountCollectionDefault) GetPayload() *models.MsaAggregatesResponse {
	return o.Payload
}

func (o *AggregateDeviceCountCollectionDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MsaAggregatesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
