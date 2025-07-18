// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ItautomationTaskStageExecutionStatus itautomation task stage execution status
//
// swagger:model itautomation.TaskStageExecutionStatus
type ItautomationTaskStageExecutionStatus struct {

	// Percentage of task execution completion. Example: 75.5
	// Required: true
	CompletionPercentage *float64 `json:"completion_percentage"`

	// Timestamp when execution completed. Example: 2025-01-23T18:49:26.785778Z
	// Required: true
	// Format: date-time
	EndTime *strfmt.DateTime `json:"end_time"`

	// Host count statistics for query stage
	QueryStageStats *ItautomationAggregateHostCount `json:"query_stage_stats,omitempty"`

	// Host count statistics for remediation stage
	RemediationStageStats *ItautomationAggregateHostCount `json:"remediation_stage_stats,omitempty"`

	// Timestamp when execution started. Example: 2025-01-23T18:11:20.148439Z
	// Required: true
	// Format: date-time
	StartTime *strfmt.DateTime `json:"start_time"`

	// Current status of the task execution. Example: Running
	// Required: true
	Status *string `json:"status"`

	// Total number of hosts targeted by this execution
	// Required: true
	TotalHostCount *int64 `json:"total_host_count"`

	// Total number of results across all hosts
	TotalResults int64 `json:"total_results,omitempty"`

	// Host count statistics for verification stage
	VerificationStageStats *ItautomationAggregateHostCount `json:"verification_stage_stats,omitempty"`

	// Host count summary for verification stage
	// Required: true
	VerificationSummary *ItautomationVerificationSummary `json:"verification_summary"`
}

// Validate validates this itautomation task stage execution status
func (m *ItautomationTaskStageExecutionStatus) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCompletionPercentage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQueryStageStats(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemediationStageStats(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTotalHostCount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerificationStageStats(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVerificationSummary(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateCompletionPercentage(formats strfmt.Registry) error {

	if err := validate.Required("completion_percentage", "body", m.CompletionPercentage); err != nil {
		return err
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateEndTime(formats strfmt.Registry) error {

	if err := validate.Required("end_time", "body", m.EndTime); err != nil {
		return err
	}

	if err := validate.FormatOf("end_time", "body", "date-time", m.EndTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateQueryStageStats(formats strfmt.Registry) error {
	if swag.IsZero(m.QueryStageStats) { // not required
		return nil
	}

	if m.QueryStageStats != nil {
		if err := m.QueryStageStats.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("query_stage_stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("query_stage_stats")
			}
			return err
		}
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateRemediationStageStats(formats strfmt.Registry) error {
	if swag.IsZero(m.RemediationStageStats) { // not required
		return nil
	}

	if m.RemediationStageStats != nil {
		if err := m.RemediationStageStats.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("remediation_stage_stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("remediation_stage_stats")
			}
			return err
		}
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateStartTime(formats strfmt.Registry) error {

	if err := validate.Required("start_time", "body", m.StartTime); err != nil {
		return err
	}

	if err := validate.FormatOf("start_time", "body", "date-time", m.StartTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateTotalHostCount(formats strfmt.Registry) error {

	if err := validate.Required("total_host_count", "body", m.TotalHostCount); err != nil {
		return err
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateVerificationStageStats(formats strfmt.Registry) error {
	if swag.IsZero(m.VerificationStageStats) { // not required
		return nil
	}

	if m.VerificationStageStats != nil {
		if err := m.VerificationStageStats.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verification_stage_stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verification_stage_stats")
			}
			return err
		}
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) validateVerificationSummary(formats strfmt.Registry) error {

	if err := validate.Required("verification_summary", "body", m.VerificationSummary); err != nil {
		return err
	}

	if m.VerificationSummary != nil {
		if err := m.VerificationSummary.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verification_summary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verification_summary")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this itautomation task stage execution status based on the context it is used
func (m *ItautomationTaskStageExecutionStatus) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateQueryStageStats(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemediationStageStats(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVerificationStageStats(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVerificationSummary(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ItautomationTaskStageExecutionStatus) contextValidateQueryStageStats(ctx context.Context, formats strfmt.Registry) error {

	if m.QueryStageStats != nil {

		if swag.IsZero(m.QueryStageStats) { // not required
			return nil
		}

		if err := m.QueryStageStats.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("query_stage_stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("query_stage_stats")
			}
			return err
		}
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) contextValidateRemediationStageStats(ctx context.Context, formats strfmt.Registry) error {

	if m.RemediationStageStats != nil {

		if swag.IsZero(m.RemediationStageStats) { // not required
			return nil
		}

		if err := m.RemediationStageStats.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("remediation_stage_stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("remediation_stage_stats")
			}
			return err
		}
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) contextValidateVerificationStageStats(ctx context.Context, formats strfmt.Registry) error {

	if m.VerificationStageStats != nil {

		if swag.IsZero(m.VerificationStageStats) { // not required
			return nil
		}

		if err := m.VerificationStageStats.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verification_stage_stats")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verification_stage_stats")
			}
			return err
		}
	}

	return nil
}

func (m *ItautomationTaskStageExecutionStatus) contextValidateVerificationSummary(ctx context.Context, formats strfmt.Registry) error {

	if m.VerificationSummary != nil {

		if err := m.VerificationSummary.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("verification_summary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("verification_summary")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ItautomationTaskStageExecutionStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ItautomationTaskStageExecutionStatus) UnmarshalBinary(b []byte) error {
	var res ItautomationTaskStageExecutionStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
