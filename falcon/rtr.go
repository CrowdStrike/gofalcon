package falcon

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

type RTR struct {
	client      real_time_response.ClientService
	adminClient real_time_response_admin.ClientService
}

func NewRTR(apiCfg *ApiConfig) (*RTR, error) {
	client, err := NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	return &RTR{client: client.RealTimeResponse, adminClient: client.RealTimeResponseAdmin}, nil
}

type RTRSession struct {
	client      real_time_response.ClientService
	adminClient real_time_response_admin.ClientService
	sessionId   string
}

func (r *RTR) ActiveSessions(ctx context.Context) ([]RTRSession, error) {
	sessions, err := r.getActiveSessions(ctx)
	if err != nil {
		return nil, err
	}

	result := []RTRSession{}
	for _, s := range sessions {
		result = append(result, RTRSession{
			client:      r.client,
			adminClient: r.adminClient,
			sessionId:   *s.ID,
		})
	}
	return result, nil
}

func (r *RTR) getActiveSessions(ctx context.Context) ([]*models.DomainSession, error) {
	sessionIds, err := r.getActiveSessionIds(ctx)
	if err != nil {
		return nil, err
	}
	response, err := r.client.RTRListSessions(&real_time_response.RTRListSessionsParams{
		Context: ctx,
		Body: &models.MsaIdsRequest{
			Ids: sessionIds,
		},
	})
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Resources, nil
}

func (r *RTR) getActiveSessionIds(ctx context.Context) ([]string, error) {
	activeQuery := "deleted_at:NULL"
	response, err := r.client.RTRListAllSessions(&real_time_response.RTRListAllSessionsParams{
		Context: ctx,
		Filter:  &activeQuery,
	})
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.GetPayload().Resources, nil
}

func (r *RTR) NewSession(ctx context.Context, deviceID string) (*RTRSession, error) {
	response, err := r.client.RTRInitSession(&real_time_response.RTRInitSessionParams{
		Body: &models.DomainInitRequest{
			DeviceID: &deviceID,
		},
		Context: ctx,
	})
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	if len(response.Payload.Resources) != 1 {
		return nil, fmt.Errorf("Unexpected return from RTRInitSession: %v", response)
	}
	return &RTRSession{
		client:      r.client,
		adminClient: r.adminClient,
		sessionId:   *response.GetPayload().Resources[0].SessionID,
	}, nil
}

func (s RTRSession) ExecuteAndWait(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	execution, err := s.Execute(ctx, baseCommand, commandString, opts...)
	if err != nil {
		return nil, err
	}
	return s.WaitForExecution(ctx, *execution.CloudRequestID, opts...)
}

func (s RTRSession) ActiveResponderExecuteAndWait(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	execution, err := s.ActiveResponderExecute(ctx, baseCommand, commandString, opts...)
	if err != nil {
		return nil, err
	}
	return s.ActiveResponderWaitForExecution(ctx, *execution.CloudRequestID, opts...)
}

func (s RTRSession) AdminExecuteAndWait(ctx context.Context, baseCommand, commandString string, opts ...real_time_response_admin.ClientOption) (*models.DomainStatusResponse, error) {
	execution, err := s.AdminExecute(ctx, baseCommand, commandString, opts...)
	if err != nil {
		return nil, err
	}
	return s.AdminWaitForExecution(ctx, *execution.CloudRequestID, opts...)
}

func (s RTRSession) Execute(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainCommandExecuteResponse, error) {
	response, err := s.client.RTRExecuteCommand(&real_time_response.RTRExecuteCommandParams{
		Context: ctx,
		Body: &models.DomainCommandExecuteRequest{
			BaseCommand:   &baseCommand,
			CommandString: &commandString,
			SessionID:     &s.sessionId,
		},
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	if len(response.Payload.Resources) != 1 {
		return nil, fmt.Errorf("Expected one RTRExecuteResponse object got %d: %v", len(response.Payload.Resources), response.Payload.Resources)
	}
	return response.Payload.Resources[0], nil
}

func (s RTRSession) ActiveResponderExecute(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainCommandExecuteResponse, error) {
	response, err := s.client.RTRExecuteActiveResponderCommand(&real_time_response.RTRExecuteActiveResponderCommandParams{
		Context: ctx,
		Body: &models.DomainCommandExecuteRequest{
			BaseCommand:   &baseCommand,
			CommandString: &commandString,
			SessionID:     &s.sessionId,
		},
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	if len(response.Payload.Resources) != 1 {
		return nil, fmt.Errorf("Expected one RTRExecuteActiveResponderResponse object got %d: %v", len(response.Payload.Resources), response.Payload.Resources)
	}
	return response.Payload.Resources[0], nil
}

func (s RTRSession) AdminExecute(ctx context.Context, baseCommand, commandString string, opts ...real_time_response_admin.ClientOption) (*models.DomainCommandExecuteResponse, error) {
	response, err := s.adminClient.RTRExecuteAdminCommand(&real_time_response_admin.RTRExecuteAdminCommandParams{
		Context: ctx,
		Body: &models.DomainCommandExecuteRequest{
			BaseCommand:   &baseCommand,
			CommandString: &commandString,
			SessionID:     &s.sessionId,
		},
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	if len(response.Payload.Resources) != 1 {
		return nil, fmt.Errorf("Expected one RTRExecuteActiveResponderResponse object got %d: %v", len(response.Payload.Resources), response.Payload.Resources)
	}
	return response.Payload.Resources[0], nil
}

func (s *RTRSession) WaitForExecution(ctx context.Context, cloudRequestId string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	for {
		response, err := s.client.RTRCheckCommandStatus(&real_time_response.RTRCheckCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
		}, opts...)
		if err != nil {
			return nil, err
		}
		if err = AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}
		if len(response.Payload.Resources) != 1 {
			return nil, fmt.Errorf("Unexpected return from RTRCheckActiverResponderCommandStatus: %v", response)
		}
		if *response.Payload.Resources[0].Complete {
			return response.Payload.Resources[0], nil
		}
		time.Sleep(120 * time.Millisecond)
	}
}

func (s *RTRSession) ActiveResponderWaitForExecution(ctx context.Context, cloudRequestId string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	for {
		response, err := s.client.RTRCheckActiveResponderCommandStatus(&real_time_response.RTRCheckActiveResponderCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
		}, opts...)
		if err != nil {
			return nil, err
		}
		if err = AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}
		if len(response.Payload.Resources) != 1 {
			return nil, fmt.Errorf("Unexpected return from RTRCheckActiverResponderCommandStatus: %v", response)
		}
		if *response.Payload.Resources[0].Complete {
			return response.Payload.Resources[0], nil
		}
		time.Sleep(120 * time.Millisecond)
	}
}

func (s *RTRSession) AdminWaitForExecution(ctx context.Context, cloudRequestId string, opts ...real_time_response_admin.ClientOption) (*models.DomainStatusResponse, error) {
	for {
		response, err := s.adminClient.RTRCheckAdminCommandStatus(&real_time_response_admin.RTRCheckAdminCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
		}, opts...)
		if err != nil {
			return nil, err
		}
		if err = AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}
		if len(response.Payload.Resources) != 1 {
			return nil, fmt.Errorf("Unexpected return from RTRCheckActiverResponderCommandStatus: %v", response)
		}
		if *response.Payload.Resources[0].Complete {
			return response.Payload.Resources[0], nil
		}
		time.Sleep(120 * time.Millisecond)
	}
}

func (s *RTRSession) ListFiles(ctx context.Context) ([]*models.DomainFileV2, error) {
	response, err := s.client.RTRListFilesV2(&real_time_response.RTRListFilesV2Params{
		Context:   ctx,
		SessionID: s.sessionId,
	})
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Resources, nil
}

func (s *RTRSession) GetFile(ctx context.Context, sha256, filePath string, output io.Writer) error {
	_, err := s.client.RTRGetExtractedFileContents(&real_time_response.RTRGetExtractedFileContentsParams{
		Context:   ctx,
		SessionID: s.sessionId,
		Sha256:    sha256,
		Filename:  &filePath,
	}, output)
	return err
}

func (s *RTRSession) Close(ctx context.Context) error {
	response, err := s.client.RTRDeleteSession(&real_time_response.RTRDeleteSessionParams{
		Context:   ctx,
		SessionID: s.sessionId,
	})
	if err != nil {
		return err
	}
	return AssertNoError(response.Payload.Errors)
}

func (r *RTR) PulseSession(ctx context.Context, request *models.DomainInitRequest) (*RTRSession, error) {
	response, err := r.client.RTRPulseSession(&real_time_response.RTRPulseSessionParams{
		Context: ctx,
		Body:    request,
	})
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	if len(response.Payload.Resources) != 1 {
		return nil, fmt.Errorf("Unexpected return from RTRPulseSession: %v", response)
	}
	return &RTRSession{
		client:      r.client,
		adminClient: r.adminClient,
		sessionId:   *response.GetPayload().Resources[0].SessionID,
	}, nil
}
