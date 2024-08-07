// Code generated by go-swagger; DO NOT EDIT.

package host_migration

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new host migration API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for host migration API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateMigrationV1(params *CreateMigrationV1Params, opts ...ClientOption) (*CreateMigrationV1Created, error)

	GetHostMigrationIDsV1(params *GetHostMigrationIDsV1Params, opts ...ClientOption) (*GetHostMigrationIDsV1OK, error)

	GetHostMigrationsV1(params *GetHostMigrationsV1Params, opts ...ClientOption) (*GetHostMigrationsV1OK, error)

	GetMigrationDestinationsV1(params *GetMigrationDestinationsV1Params, opts ...ClientOption) (*GetMigrationDestinationsV1OK, error)

	GetMigrationIDsV1(params *GetMigrationIDsV1Params, opts ...ClientOption) (*GetMigrationIDsV1OK, error)

	GetMigrationsV1(params *GetMigrationsV1Params, opts ...ClientOption) (*GetMigrationsV1OK, error)

	HostMigrationAggregatesV1(params *HostMigrationAggregatesV1Params, opts ...ClientOption) (*HostMigrationAggregatesV1OK, error)

	HostMigrationsActionsV1(params *HostMigrationsActionsV1Params, opts ...ClientOption) (*HostMigrationsActionsV1OK, error)

	MigrationAggregatesV1(params *MigrationAggregatesV1Params, opts ...ClientOption) (*MigrationAggregatesV1OK, error)

	MigrationsActionsV1(params *MigrationsActionsV1Params, opts ...ClientOption) (*MigrationsActionsV1OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateMigrationV1 creates a device migration job

`device_ids` and `filter` are mutually exclusive. Filter takes precedence.
*/
func (a *Client) CreateMigrationV1(params *CreateMigrationV1Params, opts ...ClientOption) (*CreateMigrationV1Created, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateMigrationV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateMigrationV1",
		Method:             "POST",
		PathPattern:        "/host-migration/entities/migrations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateMigrationV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateMigrationV1Created)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateMigrationV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetHostMigrationIDsV1 queries host migration i ds

Query host migration IDs.
*/
func (a *Client) GetHostMigrationIDsV1(params *GetHostMigrationIDsV1Params, opts ...ClientOption) (*GetHostMigrationIDsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetHostMigrationIDsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetHostMigrationIDsV1",
		Method:             "GET",
		PathPattern:        "/host-migration/queries/host-migrations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetHostMigrationIDsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetHostMigrationIDsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetHostMigrationIDsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetHostMigrationsV1 gets host migration details

	# Events

The `events` field describes actions that have occurred to the host migration entity. Each object is defined by the `action` field. When `user` is present, it is the user who performed the action. `time` is when the action occurred.

## Event actions

### added

This action is emitted when the host migration is created.

```
{ "action": "added", "user": "example@example.com", "time": "2024-01-01T00:00:00Z" }
```

### assigned_static_host_groups

This action is emitted when a user assigns static host groups to a host migration. `ids` are the ids of the new host groups that have been assigned.

```
{ "action": "assigned_static_host_groups", "ids": ["foo", "bar"],  "user": "example@example.com", "time": "2024-01-01T00:00:00Z" }
```

### removed_static_host_groups

This action is emitted when a user removes static host groups from a host migration. `ids` are the ids of the host groups that have been removed.

```
{ "action": "removed_static_host_groups", "ids": ["foo", "bar"],  "user": "example@example.com", "time": "2024-01-01T00:00:00Z" }
```

### queued

This action is emitted when the migration is started.

```
{ "action": "queued", "user": "example@example.com", "time": "2024-01-01T00:00:00Z" }
```

### failed

This action is emitted when the host migration fails. `reason` is the reason for failure. `reason` can be `unsupported_sensor_version`, `unsupported_sensor_platform`, `host_missing`, `migration_expired`, or `internal_error`.

```
{ "action": "failed", "reason": "unsupported_sensor_version", "time": "2024-01-01T00:00:00Z" }
```

### cancelled

This action is emitted when the migration has been cancelled.

```
{ "action": "cancelled", "user": "example@example.com", "time": "2024-01-01T00:00:00Z" }
```

### completed

This action is emitted when the host has successfully migrated.

```
{ "action": "completed", "time": "2024-01-01T00:00:00Z" }
```

# Status Details

The `status_details` field is an optional field that provides some more details about the status of a failed host migration.
It may be omitted or empty from a response.

### internal_error

This status detail is provided when an internal occurs during a host migration.

### canceled_by_user

This status detail is provided when a migration has been canceled by a user.

### host_missing

This status detail is provided when a host migration is canceled because the source host can no longer be found.

### migration_expired

This status detail is provided when a host migration is expired because the migration is too old.

### migration_already_in_progress

This status detail is provided when attempting to start a host migration on a host that is already in progress in another migration.

### source_host_unsupported_version

This status detail is provided when attempting to create or start a host migration when the sensor is on an unsupported version.

### source_host_unsupported_platform

This status detail is provided when attempting to create or start a host migration when the sensor is an unsupported platform.
*/
func (a *Client) GetHostMigrationsV1(params *GetHostMigrationsV1Params, opts ...ClientOption) (*GetHostMigrationsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetHostMigrationsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetHostMigrationsV1",
		Method:             "POST",
		PathPattern:        "/host-migration/entities/host-migrations/GET/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetHostMigrationsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetHostMigrationsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetHostMigrationsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetMigrationDestinationsV1 gets destinations for a migration

`device_ids` and `filter` are mutually exclusive.
*/
func (a *Client) GetMigrationDestinationsV1(params *GetMigrationDestinationsV1Params, opts ...ClientOption) (*GetMigrationDestinationsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMigrationDestinationsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMigrationDestinationsV1",
		Method:             "POST",
		PathPattern:        "/host-migration/entities/migration-destinations/GET/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMigrationDestinationsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetMigrationDestinationsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMigrationDestinationsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetMigrationIDsV1 queries migration jobs
*/
func (a *Client) GetMigrationIDsV1(params *GetMigrationIDsV1Params, opts ...ClientOption) (*GetMigrationIDsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMigrationIDsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMigrationIDsV1",
		Method:             "GET",
		PathPattern:        "/host-migration/queries/migrations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMigrationIDsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetMigrationIDsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMigrationIDsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetMigrationsV1 gets migration job details
*/
func (a *Client) GetMigrationsV1(params *GetMigrationsV1Params, opts ...ClientOption) (*GetMigrationsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetMigrationsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetMigrationsV1",
		Method:             "GET",
		PathPattern:        "/host-migration/entities/migrations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetMigrationsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetMigrationsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetMigrationsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	HostMigrationAggregatesV1 gets host migration aggregates as specified via json in request body

	Get host migration aggregates as specified via json in request body.

# Supported Types

Both types support the following FQL filter properties: `groups`, `hostgroups`, `static_host_groups`, `hostname`, `status`, `target_cid`, `source_cid`, `migration_id`, `id`, `host_migration_id`, `created_time`.

The values `groups` and `hostgroups` are aliases for `static_host_groups`.

The value `host_migration_id` is an alias for `id`

## Terms
`"type": "terms"`

Supported `field` values: `groups`, `hostgroups`, `static_host_groups`, `hostname`, `status`, `target_cid`, `source_cid`, `migration_id`, `id`, `host_migration_id`.

`sort` must be done on the same value as `field` and include a direction (`asc` or `desc`). Supports all FQL fields except for `groups`, `hostgroups`, or `static_host_groups`.

Examples sort value: `status|asc` or `created_by|desc`

## Date Range
`"type": "date_range"`

Supported `field` fields: `created_time`.

Does not support `sort`, `size`, or `from`.
*/
func (a *Client) HostMigrationAggregatesV1(params *HostMigrationAggregatesV1Params, opts ...ClientOption) (*HostMigrationAggregatesV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewHostMigrationAggregatesV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "HostMigrationAggregatesV1",
		Method:             "POST",
		PathPattern:        "/host-migration/aggregates/host-migrations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &HostMigrationAggregatesV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*HostMigrationAggregatesV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for HostMigrationAggregatesV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	HostMigrationsActionsV1 performs an action on host migrations

	The available actions are `add_host_groups`, `remove_host_groups`, and `remove_hosts`.

FQL filter supports the following fields: `groups`, `hostgroups`, `static_host_groups`, `hostname`, `status`, `target_cid`, `source_cid`, `migration_id`, `id`, `host_migration_id`, `created_time`.

These actions only works if the migration has not started.

`add_host_groups` adds static host groups to the selected hosts in a migration. This action accepts the following action parameter: `{ "name": "host_group": "value": "$host_group_id" }`. Action parameters can be repeated to add multiple static host groups in a single request.

`remove_host_groups` removes static host groups from the selected hosts in a migration. This action accepts the following action parameter: `{ "name": "host_group": "value": "$host_group_id" }`. Action parameters can be repeated to remove multiple static host groups in a single request.

`remove_hosts` removes the selected hosts from a migration. This action does not accept any action parameters.
*/
func (a *Client) HostMigrationsActionsV1(params *HostMigrationsActionsV1Params, opts ...ClientOption) (*HostMigrationsActionsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewHostMigrationsActionsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "HostMigrationsActionsV1",
		Method:             "POST",
		PathPattern:        "/host-migration/entities/host-migrations-actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &HostMigrationsActionsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*HostMigrationsActionsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for HostMigrationsActionsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	MigrationAggregatesV1 gets migration aggregates as specified via json in request body

	Get migration aggregates as specified via json in request body.

# Supported Types

Both types support the following FQL filter props: `name`, `id`, `migration_id`, `target_cid`, `status`, `migration_status`, `created_by`, `created_time`.

The value `migration_status` is an alias for `status`.

The value `migration_id` is an alias for `id`.

## Terms
`"type": "terms"`

Supported `field` values: `name`, `id`, `migration_id,` `target_cid`, `status`, `migration_status`, `created_by`.

`sort` on `terms` type must be done on the same value as `field` and include a direction (`asc` or `desc`). Supports all supported FQL fields.

Examples sort value: `status|asc` or `created_by|desc`.

## Date Range
`"type": "date_range"`

Supported `field` fields: `created_time`.

Does not support `sort`, `size`, or `from`.
*/
func (a *Client) MigrationAggregatesV1(params *MigrationAggregatesV1Params, opts ...ClientOption) (*MigrationAggregatesV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewMigrationAggregatesV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "MigrationAggregatesV1",
		Method:             "POST",
		PathPattern:        "/host-migration/aggregates/migrations/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &MigrationAggregatesV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*MigrationAggregatesV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for MigrationAggregatesV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	MigrationsActionsV1 performs an action on a migration job

	The available actions are `start_migration`, `cancel_migration`, `rename_migration`, and `delete_migration`.

`start_migration` starts the selected migrations. This action only works if the migration has not started. This action does not accept any action parameters. Only one migration may be started per request.

`cancel_migration` cancels the selected migrations. This actions only works if the migration has started and not completed. This action does not accept any action parameters.

`rename_migration` renames the selected migrations. This action can be called at any time. Only 1 action parameter may be supplied. Action parameters take the form of `{"name": "migration_name": "value": "$new_migration_name"}`.

`delete_migration` deletes the selected migrations. This action only works if the migration has not started. This action does not accept any action parameters.
*/
func (a *Client) MigrationsActionsV1(params *MigrationsActionsV1Params, opts ...ClientOption) (*MigrationsActionsV1OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewMigrationsActionsV1Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "MigrationsActionsV1",
		Method:             "POST",
		PathPattern:        "/host-migration/entities/migrations-actions/v1",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &MigrationsActionsV1Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*MigrationsActionsV1OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for MigrationsActionsV1: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
