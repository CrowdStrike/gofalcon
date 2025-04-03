package falcon

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/go-openapi/runtime"
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

func (r *RTR) CreateScript(ctx context.Context, name *string, description, permissionType string, platform []string, auditLogComment, content *string, file runtime.NamedReadCloser, opts ...real_time_response_admin.ClientOption) error {
	response, err := r.adminClient.RTRCreateScripts(&real_time_response_admin.RTRCreateScriptsParams{
		CommentsForAuditLog: auditLogComment,
		Content:             content,
		Description:         description,
		File:                file,
		Name:                name,
		PermissionType:      permissionType,
		Platform:            platform,
		Context:             ctx,
	}, opts...)
	if err != nil {
		return err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return err
	}
	count := falcon_util.DerefInt32(response.Payload.Meta.Writes.ResourcesAffected)
	if count != 1 {
		return fmt.Errorf("expected 1 resource affected, got %d", count)
	}
	return nil
}

func (r *RTR) UpdateScript(ctx context.Context, id string, name, description, permissionType *string, platform []string, auditLogComment, content *string, file runtime.NamedReadCloser, opts ...real_time_response_admin.ClientOption) error {
	response, err := r.adminClient.RTRUpdateScripts(&real_time_response_admin.RTRUpdateScriptsParams{
		CommentsForAuditLog: auditLogComment,
		Content:             content,
		Description:         description,
		File:                file,
		ID:                  id,
		Name:                name,
		PermissionType:      permissionType,
		Platform:            platform,
		Context:             ctx,
	}, opts...)
	if err != nil {
		return err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return err
	}
	count := falcon_util.DerefInt32(response.Payload.Meta.Writes.ResourcesAffected)
	if count != 1 {
		return fmt.Errorf("expected 1 resource affected, got %d", count)
	}
	return nil
}

func (r *RTR) DeleteScript(ctx context.Context, id string, opts ...real_time_response_admin.ClientOption) error {
	response, err := r.adminClient.RTRDeleteScripts(&real_time_response_admin.RTRDeleteScriptsParams{
		Ids:     id,
		Context: ctx,
	}, opts...)
	if err != nil {
		return err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return err
	}
	count := falcon_util.DerefInt32(response.Payload.Meta.Writes.ResourcesAffected)
	if count != 1 {
		return fmt.Errorf("expected 1 resource affected, got %d", count)
	}
	return nil
}

func (r *RTR) GetScripts(ctx context.Context, ids []string, opts ...real_time_response_admin.ClientOption) ([]*models.EmpowerapiRemoteCommandPutFileV2, error) {
	response, err := r.adminClient.RTRGetScriptsV2(&real_time_response_admin.RTRGetScriptsV2Params{
		Ids:     ids,
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Resources, nil
}

func (r *RTR) ListScripts(ctx context.Context, filter *string, limit *int64, offset, sort *string, opts ...real_time_response_admin.ClientOption) (*models.BinservapiMsaPutFileResponse, error) {
	response, err := r.adminClient.RTRListScripts(&real_time_response_admin.RTRListScriptsParams{
		Filter:  filter,
		Limit:   limit,
		Offset:  offset,
		Sort:    sort,
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload, nil
}

func (r *RTR) CreatePutFile(ctx context.Context, name *string, description string, auditLogComment *string, file runtime.NamedReadCloser, opts ...real_time_response_admin.ClientOption) error {
	response, err := r.adminClient.RTRCreatePutFiles(&real_time_response_admin.RTRCreatePutFilesParams{
		CommentsForAuditLog: auditLogComment,
		Description:         description,
		File:                file,
		Name:                name,
		Context:             ctx,
	}, opts...)
	if err != nil {
		return err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return err
	}
	count := falcon_util.DerefInt32(response.Payload.Meta.Writes.ResourcesAffected)
	if count != 1 {
		return fmt.Errorf("expected 1 resource affected, got %d", count)
	}
	return nil
}

func (r *RTR) DeletePutFile(ctx context.Context, id string, opts ...real_time_response_admin.ClientOption) error {
	response, err := r.adminClient.RTRDeletePutFiles(&real_time_response_admin.RTRDeletePutFilesParams{
		Ids:     id,
		Context: ctx,
	}, opts...)
	if err != nil {
		return err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return err
	}
	count := falcon_util.DerefInt32(response.Payload.Meta.Writes.ResourcesAffected)
	if count != 1 {
		return fmt.Errorf("expected 1 resource affected, got %d", count)
	}
	return nil
}

func (r *RTR) GetPutFiles(ctx context.Context, ids []string, opts ...real_time_response_admin.ClientOption) ([]*models.EmpowerapiRemoteCommandPutFileV2, error) {
	response, err := r.adminClient.RTRGetPutFilesV2(&real_time_response_admin.RTRGetPutFilesV2Params{
		Ids:     ids,
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Resources, nil
}

func (r *RTR) ListPutFiles(ctx context.Context, filter *string, limit *int64, offset, sort *string, opts ...real_time_response_admin.ClientOption) (*models.BinservapiMsaPutFileResponse, error) {
	response, err := r.adminClient.RTRListPutFiles(&real_time_response_admin.RTRListPutFilesParams{
		Filter:  filter,
		Limit:   limit,
		Offset:  offset,
		Sort:    sort,
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload, nil
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
		return nil, fmt.Errorf("unexpected return from RTRInitSession: %v", response)
	}
	return &RTRSession{
		client:      r.client,
		adminClient: r.adminClient,
		sessionId:   *response.GetPayload().Resources[0].SessionID,
	}, nil
}

func (s *RTRSession) ExecuteAndWait(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	execution, err := s.Execute(ctx, baseCommand, commandString, opts...)
	if err != nil {
		return nil, err
	}
	return s.WaitForExecution(ctx, *execution.CloudRequestID, opts...)
}

func (s *RTRSession) ActiveResponderExecuteAndWait(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	execution, err := s.ActiveResponderExecute(ctx, baseCommand, commandString, opts...)
	if err != nil {
		return nil, err
	}
	return s.ActiveResponderWaitForExecution(ctx, *execution.CloudRequestID, opts...)
}

func (s *RTRSession) AdminExecuteAndWait(ctx context.Context, baseCommand, commandString string, opts ...real_time_response_admin.ClientOption) (*models.DomainStatusResponse, error) {
	execution, err := s.AdminExecute(ctx, baseCommand, commandString, opts...)
	if err != nil {
		return nil, err
	}
	return s.AdminWaitForExecution(ctx, *execution.CloudRequestID, opts...)
}

func (s *RTRSession) Execute(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainCommandExecuteResponse, error) {
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
		return nil, fmt.Errorf("expected one RTRExecuteResponse object got %d: %v", len(response.Payload.Resources), response.Payload.Resources)
	}
	return response.Payload.Resources[0], nil
}

func (s *RTRSession) ActiveResponderExecute(ctx context.Context, baseCommand, commandString string, opts ...real_time_response.ClientOption) (*models.DomainCommandExecuteResponse, error) {
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
		return nil, fmt.Errorf("expected one RTRExecuteActiveResponderResponse object got %d: %v", len(response.Payload.Resources), response.Payload.Resources)
	}
	return response.Payload.Resources[0], nil
}

func (s *RTRSession) AdminExecute(ctx context.Context, baseCommand, commandString string, opts ...real_time_response_admin.ClientOption) (*models.DomainCommandExecuteResponse, error) {
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
		return nil, fmt.Errorf("expected one RTRExecuteActiveResponderResponse object got %d: %v", len(response.Payload.Resources), response.Payload.Resources)
	}
	return response.Payload.Resources[0], nil
}

func (s *RTRSession) WaitForExecution(ctx context.Context, cloudRequestId string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	var lastSequenceID int64 = 0
	var completeResponse = models.DomainStatusResponse{
		Stdout: new(string),
		Stderr: new(string),
	}

	for {
		response, err := s.client.RTRCheckCommandStatus(&real_time_response.RTRCheckCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
			SequenceID:     lastSequenceID,
		}, opts...)
		if err != nil {
			return nil, err
		}
		if err = AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}
		if len(response.Payload.Resources) != 1 {
			return nil, fmt.Errorf("unexpected return from RTRCheckActiverResponderCommandStatus: %v", response)
		}
		resource := *response.Payload.Resources[0]
		*completeResponse.Stderr += falcon_util.DerefString(resource.Stderr)
		*completeResponse.Stdout += falcon_util.DerefString(resource.Stdout)
		if *resource.Complete {
			completeResponse.BaseCommand = resource.BaseCommand
			completeResponse.Complete = resource.Complete
			completeResponse.SequenceID = resource.SequenceID
			completeResponse.SessionID = resource.SessionID
			completeResponse.TaskID = resource.TaskID
			return &completeResponse, nil
		}
		lastSequenceID = resource.SequenceID
		time.Sleep(120 * time.Millisecond)
	}
}

func (s *RTRSession) ActiveResponderWaitForExecution(ctx context.Context, cloudRequestId string, opts ...real_time_response.ClientOption) (*models.DomainStatusResponse, error) {
	var lastSequenceID int64 = 0
	var completeResponse = models.DomainStatusResponse{
		Stdout: new(string),
		Stderr: new(string),
	}
	for {
		response, err := s.client.RTRCheckActiveResponderCommandStatus(&real_time_response.RTRCheckActiveResponderCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
			SequenceID:     lastSequenceID,
		}, opts...)
		if err != nil {
			return nil, err
		}
		if err = AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}
		if len(response.Payload.Resources) != 1 {
			return nil, fmt.Errorf("unexpected return from RTRCheckActiverResponderCommandStatus: %v", response)
		}
		resource := *response.Payload.Resources[0]
		*completeResponse.Stderr += falcon_util.DerefString(resource.Stderr)
		*completeResponse.Stdout += falcon_util.DerefString(resource.Stdout)
		if *resource.Complete {
			completeResponse.BaseCommand = resource.BaseCommand
			completeResponse.Complete = resource.Complete
			completeResponse.SequenceID = resource.SequenceID
			completeResponse.SessionID = resource.SessionID
			completeResponse.TaskID = resource.TaskID
			return &completeResponse, nil
		}
		lastSequenceID = resource.SequenceID
		time.Sleep(120 * time.Millisecond)
	}
}

func (s *RTRSession) AdminWaitForExecution(ctx context.Context, cloudRequestId string, opts ...real_time_response_admin.ClientOption) (*models.DomainStatusResponse, error) {
	var lastSequenceID int64 = 0
	var completeResponse = models.DomainStatusResponse{
		Stdout: new(string),
		Stderr: new(string),
	}
	for {
		response, err := s.adminClient.RTRCheckAdminCommandStatus(&real_time_response_admin.RTRCheckAdminCommandStatusParams{
			Context:        ctx,
			CloudRequestID: cloudRequestId,
			SequenceID:     lastSequenceID,
		}, opts...)
		if err != nil {
			return nil, err
		}
		if err = AssertNoError(response.Payload.Errors); err != nil {
			return nil, err
		}
		if len(response.Payload.Resources) != 1 {
			return nil, fmt.Errorf("unexpected return from RTRCheckActiverResponderCommandStatus: %v", response)
		}
		resource := *response.Payload.Resources[0]
		*completeResponse.Stderr += falcon_util.DerefString(resource.Stderr)
		*completeResponse.Stdout += falcon_util.DerefString(resource.Stdout)
		if *resource.Complete {
			completeResponse.BaseCommand = resource.BaseCommand
			completeResponse.Complete = resource.Complete
			completeResponse.SequenceID = resource.SequenceID
			completeResponse.SessionID = resource.SessionID
			completeResponse.TaskID = resource.TaskID
			return &completeResponse, nil
		}
		lastSequenceID = resource.SequenceID
		time.Sleep(120 * time.Millisecond)
	}
}

// NewBatchSession initiates a batch session for the given hosts. Use the returned BatchID in subsequent call via the
// command methods in this type to then execute RTR commands on them.
// timeout and timeoutDuration are pointers because only one is required and they are mutually exclusive. timeoutDuration is preferred.
func (r *RTR) NewBatchSession(ctx context.Context, timeout *int64, timeoutDuration *time.Duration, hostTimeoutDuration time.Duration, hostIDs []string, existingBatchID *string, queueOffline bool, opts ...real_time_response.ClientOption) (*models.DomainBatchInitSessionResponse, error) {
	var timeoutDurationParam *string = nil
	if timeoutDuration != nil {
		timeoutDurationParam = falcon_util.StrPtr(timeoutDuration.String())
	}
	response, err := r.client.BatchInitSessions(&real_time_response.BatchInitSessionsParams{
		Timeout:             timeout,
		TimeoutDuration:     timeoutDurationParam,
		HostTimeoutDuration: falcon_util.StrPtr(hostTimeoutDuration.String()),
		Body: &models.DomainBatchInitSessionRequest{
			ExistingBatchID: existingBatchID,
			HostIds:         hostIDs,
			QueueOffline:    &queueOffline,
		},
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload, nil
}

// BatchCmd executes an RTR Read Only Analyst command against a batch of hosts.
// timeout and timeoutDuration are pointers because only one is required and they are mutually exclusive. timeoutDuration is preferred.
func (r *RTR) BatchCmd(ctx context.Context, timeout *int64, timeoutDuration *time.Duration, hostTimeoutDuration time.Duration,
	baseCommand, batchID, commandString string, optionalHosts []string, opts ...real_time_response.ClientOption) (map[string]models.DomainMultiStatusSensorResponse, error) {

	var timeoutDurationParam *string = nil
	if timeoutDuration != nil {
		timeoutDurationParam = falcon_util.StrPtr(timeoutDuration.String())
	}
	response, err := r.client.BatchCmd(&real_time_response.BatchCmdParams{
		HostTimeoutDuration: falcon_util.StrPtr(hostTimeoutDuration.String()),
		Timeout:             timeout,
		TimeoutDuration:     timeoutDurationParam,
		Body: &models.DomainBatchExecuteCommandRequest{
			BaseCommand:   &baseCommand,
			BatchID:       &batchID,
			CommandString: &commandString,
			OptionalHosts: optionalHosts,
		},
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Combined.Resources, nil
}

// BatchActiveResponderCmd executes an RTR Active Responder command against a batch of hosts.
// timeout and timeoutDuration are pointers because only one is required and they are mutually exclusive. timeoutDuration is preferred.
func (r *RTR) BatchActiveResponderCmd(ctx context.Context, timeout *int64, timeoutDuration *time.Duration, hostTimeoutDuration time.Duration,
	baseCommand, batchID, commandString string, optionalHosts []string, opts ...real_time_response.ClientOption) (map[string]models.DomainMultiStatusSensorResponse, error) {

	var timeoutDurationParam *string = nil
	if timeoutDuration != nil {
		timeoutDurationParam = falcon_util.StrPtr(timeoutDuration.String())
	}
	response, err := r.client.BatchActiveResponderCmd(&real_time_response.BatchActiveResponderCmdParams{
		HostTimeoutDuration: falcon_util.StrPtr(hostTimeoutDuration.String()),
		Timeout:             timeout,
		TimeoutDuration:     timeoutDurationParam,
		Body: &models.DomainBatchExecuteCommandRequest{
			BaseCommand:   &baseCommand,
			BatchID:       &batchID,
			CommandString: &commandString,
			OptionalHosts: optionalHosts,
		},
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Combined.Resources, nil
}

// BatchAdminCmd executes an RTR Admin command against a batch of hosts.
// timeout and timeoutDuration are pointers because only one is required and they are mutually exclusive. timeoutDuration is preferred.
func (r *RTR) BatchAdminCmd(ctx context.Context, timeout *int64, timeoutDuration *time.Duration, hostTimeoutDuration time.Duration,
	baseCommand, batchID, commandString string, optionalHosts []string, opts ...real_time_response_admin.ClientOption) (map[string]models.DomainMultiStatusSensorResponse, error) {

	var timeoutDurationParam *string = nil
	if timeoutDuration != nil {
		timeoutDurationParam = falcon_util.StrPtr(timeoutDuration.String())
	}
	response, err := r.adminClient.BatchAdminCmd(&real_time_response_admin.BatchAdminCmdParams{
		HostTimeoutDuration: falcon_util.StrPtr(hostTimeoutDuration.String()),
		Timeout:             timeout,
		TimeoutDuration:     timeoutDurationParam,
		Body: &models.DomainBatchExecuteCommandRequest{
			BaseCommand:   &baseCommand,
			BatchID:       &batchID,
			CommandString: &commandString,
			OptionalHosts: optionalHosts,
		},
		Context: ctx,
	}, opts...)
	if err != nil {
		return nil, err
	}
	if err = AssertNoError(response.Payload.Errors); err != nil {
		return nil, err
	}
	return response.Payload.Combined.Resources, nil
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
		return nil, fmt.Errorf("unexpected return from RTRPulseSession: %v", response)
	}
	return &RTRSession{
		client:      r.client,
		adminClient: r.adminClient,
		sessionId:   *response.GetPayload().Resources[0].SessionID,
	}, nil
}
