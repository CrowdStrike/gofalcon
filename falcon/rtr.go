package falcon

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

type RTR struct {
	cli real_time_response.ClientService
}

func NewRTR(apiCfg *ApiConfig) (*RTR, error) {
	client, err := NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	return &RTR{cli: client.RealTimeResponse}, nil
}

type RTRSession struct {
	cli       real_time_response.ClientService
	sessionId string
}

func (r *RTR) ActiveSessions(ctx context.Context) ([]RTRSession, error) {
	sessions, err := r.getActiveSessions(ctx)
	if err != nil {
		return nil, err
	}

	result := []RTRSession{}
	for _, s := range sessions {
		result = append(result, RTRSession{
			cli:       r.cli,
			sessionId: *s.ID,
		})
	}
	return result, nil
}

func (r *RTR) getActiveSessions(ctx context.Context) ([]*models.DomainSession, error) {
	sessionIds, err := r.getActiveSessionIds(ctx)
	if err != nil {
		return nil, err
	}
	response, err := r.cli.RTRListSessions(&real_time_response.RTRListSessionsParams{
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
	response, err := r.cli.RTRListAllSessions(&real_time_response.RTRListAllSessionsParams{
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
	response, err := r.cli.RTRInitSession(&real_time_response.RTRInitSessionParams{
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
		cli:       r.cli,
		sessionId: *response.GetPayload().Resources[0].SessionID,
	}, nil
}

func (s RTRSession) ExecuteAndWait(ctx context.Context, baseCommand, commandString string) (*models.DomainStatusResponse, error) {
	execution, err := s.Execute(ctx, baseCommand, commandString)
	if err != nil {
		return nil, err
	}
	return s.WaitForExecution(ctx, *execution.CloudRequestID)
}

func (s RTRSession) Execute(ctx context.Context, baseCommand, commandString string) (*models.DomainCommandExecuteResponse, error) {
	response, err := s.cli.RTRExecuteActiveResponderCommand(&real_time_response.RTRExecuteActiveResponderCommandParams{
		Context: ctx,
		Body: &models.DomainCommandExecuteRequest{
			BaseCommand:   &baseCommand,
			CommandString: &commandString,
			SessionID:     &s.sessionId,
		},
	})
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

func (s *RTRSession) WaitForExecution(ctx context.Context, cloudRequestId string) (*models.DomainStatusResponse, error) {
	for {
		response, err := s.cli.RTRCheckActiveResponderCommandStatus(&real_time_response.RTRCheckActiveResponderCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
		})
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
	response, err := s.cli.RTRListFilesV2(&real_time_response.RTRListFilesV2Params{
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
	_, err := s.cli.RTRGetExtractedFileContents(&real_time_response.RTRGetExtractedFileContentsParams{
		Context:   ctx,
		SessionID: s.sessionId,
		Sha256:    sha256,
		Filename:  &filePath,
	}, output)
	return err
}

func (s *RTRSession) Close(ctx context.Context) error {
	response, err := s.cli.RTRDeleteSession(&real_time_response.RTRDeleteSessionParams{
		Context:   ctx,
		SessionID: s.sessionId,
	})
	if err != nil {
		return err
	}
	return AssertNoError(response.Payload.Errors)
}

func (r *RTR) PulseSession(ctx context.Context, request *models.DomainInitRequest) (*RTRSession, error) {
	response, err := r.cli.RTRPulseSession(&real_time_response.RTRPulseSessionParams{
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
		cli:       r.cli,
		sessionId: *response.GetPayload().Resources[0].SessionID,
	}, nil
}
