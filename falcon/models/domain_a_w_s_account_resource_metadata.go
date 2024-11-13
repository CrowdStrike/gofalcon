// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomainAWSAccountResourceMetadata domain a w s account resource metadata
//
// swagger:model domain.AWSAccountResourceMetadata
type DomainAWSAccountResourceMetadata struct {

	// AWS CloudTrail bucket name to store logs.
	AwsCloudtrailBucketName string `json:"aws_cloudtrail_bucket_name,omitempty"`

	// AWS CloudTrail region.
	AwsCloudtrailRegion string `json:"aws_cloudtrail_region,omitempty"`

	// AWS Eventbus ARN.
	AwsEventbusArn string `json:"aws_eventbus_arn,omitempty"`

	// eventbus name
	EventbusName string `json:"eventbus_name,omitempty"`

	// ID assigned for use with cross account IAM role access.
	ExternalID string `json:"external_id,omitempty"`

	// The full arn of the IAM role created in this account to control access.
	IamRoleArn string `json:"iam_role_arn,omitempty"`

	// intermediate role arn
	IntermediateRoleArn string `json:"intermediate_role_arn,omitempty"`
}

// Validate validates this domain a w s account resource metadata
func (m *DomainAWSAccountResourceMetadata) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this domain a w s account resource metadata based on context it is used
func (m *DomainAWSAccountResourceMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainAWSAccountResourceMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainAWSAccountResourceMetadata) UnmarshalBinary(b []byte) error {
	var res DomainAWSAccountResourceMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}