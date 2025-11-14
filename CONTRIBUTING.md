# Contributing to gofalcon

## Prerequisites

- **[Go](https://golang.org/) >= 1.23.0**
- **[jq](https://jqlang.github.io/jq/) >= 1.7.1**
- **go-swagger:**
  ```bash
  go install github.com/ffalor/go-swagger/cmd/swagger@latest
  ```
- **Access to CrowdStrike Falcon console**

## Development Setup

1. Fork and clone the repository
2. Install the [prerequisites](#prerequisites)
3. Follow the [SDK Regeneration Process](#sdk-regeneration-process) to get started

## SDK Regeneration Process

The gofalcon SDK is generated from CrowdStrike's OpenAPI specifications. You can either:

- **Full regeneration**: Regenerate the entire SDK (all clients and models)
- **Selective generation**: Generate specific models, operations, or collections using the [generate tool](#the-generate-tool)

### Full SDK Regeneration

To regenerate the entire SDK:

1. **Obtain the latest swagger.json:**
   - Login to your CrowdStrike Falcon console
   - Navigate to the appropriate URL for your region:

   | Region           | URL                                                                        |
   | ---------------- | -------------------------------------------------------------------------- |
   | US-1 (preferred) | `https://assets.falcon.crowdstrike.com/support/api/swagger.json`           |
   | US-2             | `https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-mav.json`  |
   | EU-1             | `https://assets.falcon.eu-1.crowdstrike.com/support/api/swagger-lion.json` |

   - Save the file as `specs/swagger.json` in your local repository

2. **Regenerate the SDK:**
   ```bash
   make clean-generate
   ```

### Selective Generation

For targeted generation, use the [generate tool](#the-generate-tool) to generate specific parts of the SDK without regenerating everything:

```bash
# Install the tool first
make install-tools

# Generate specific models
generate model domain.IOACounts,domain.FileV2

# Generate specific operations
generate operation PostEntitiesAlertsV1

# Generate an entire collection
generate collection Alerts
```

See the [Generate Tool](#the-generate-tool) section below for more details.

## How the Generation Works

The SDK generation happens in three stages:

1. **Patch the OpenAPI Spec** (`swagger.json` → `swagger-patched.json`)
   - The `transformation.jq` file applies transformations to optimize the spec for Go code generation
   - This includes adding missing fields, correcting error codes, and consolidating duplicate type definitions
   - These transformations ensure the spec produces clean, idiomatic Go code

2. **Remove OAuth Security Definitions** (`swagger-patched.json` → `swagger-stripped-oauth.json`)
   - OAuth security definitions are stripped from the spec to create a cleaner Go interface
   - OAuth authentication is handled automatically by the SDK's middleware instead of being baked into every API call
   - This makes the generated client methods simpler to use

3. **Generate Go Client Code**
   - go-swagger generates the final Go client code from the cleaned spec
   - All files in `falcon/client/` and `falcon/models/` directories are generated from this process

## The Generate Tool

The `generate` tool located in [tools/generate/](tools/generate/) is a versatile CLI utility for selective code generation from the Swagger specification. It allows you to generate specific models, operations, or collections without regenerating the entire SDK.

### Installation

```bash
make install-tools
```

This installs the `generate` command into your `$GOPATH/bin`.

### Commands

#### Generate Models

Generate specific Go model structs from the Swagger specification:

```bash
# Generate a single model
generate model domain.IOACounts

# Generate multiple models
generate model domain.IOACounts,domain.FileV2,policymanager.ExternalPolicyPatch
```

**Example Model Structure in Swagger Spec:**

Models are defined in the `definitions` section of the spec. Here's what the `domain.IOACounts` model looks like:

```json
{
  "definitions": {
    "domain.IOACounts": {
      "required": ["critical", "high"],
      "properties": {
        "critical": {
          "type": "number",
          "format": "double"
        },
        "high": {
          "type": "number",
          "format": "double"
        },
        "informational": {
          "type": "number",
          "format": "double"
        },
        "low": {
          "type": "number",
          "format": "double"
        },
        "medium": {
          "type": "number",
          "format": "double"
        }
      }
    }
  }
}
```

The model name (e.g., `domain.IOACounts`) is what you pass to the `generate model` command.

#### Generate Endpoint

Generate Go client code for all operations on a specific endpoint path:

```bash
# Generate all operations for an endpoint
generate endpoint /alerts/entities/alerts/v2
```

This generates client code for all HTTP methods (GET, POST, PUT, DELETE, PATCH) on the specified endpoint along with only the models they reference.

**Example Endpoint Structure in Swagger Spec:**

An endpoint path can have multiple HTTP methods. Here's what the `/alerts/entities/alerts/v2` endpoint looks like:

```json
{
  "paths": {
    "/alerts/entities/alerts/v2": {
      "post": {
        "operationId": "GetV2",
        "tags": ["Alerts"],
        "summary": "Retrieves all Alerts given their composite ids."
      },
      "patch": {
        "operationId": "PatchEntitiesAlertsV2",
        "tags": ["Alerts"],
        "summary": "Perform actions on Alerts identified by composite ids."
      }
    }
  }
}
```

The endpoint path (e.g., `/alerts/entities/alerts/v2`) is what you pass to the `generate endpoint` command. This will generate client code for all operations on that endpoint (both `post` and `patch` in this example).

#### Generate Operation

Generate Go client code for a specific operation by its operation ID:

```bash
# Generate a specific operation
generate operation PostEntitiesAlertsV1
```

This generates client code for a single operation along with only the models it references.

**Example Operation Structure in Swagger Spec:**

The `operationId` identifies a specific operation in the spec. Here's what an operation looks like in our api spec.

```json
{
  "paths": {
    "/alerts/entities/alerts/v1": {
      "post": {
        "operationId": "PostEntitiesAlertsV1",
        "tags": ["Alerts"],
        "summary": "Retrieves all Alerts given their ids.",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/detectsapi.PostEntitiesAlertsV1Request"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/detectsapi.PostEntitiesAlertsV1Response"
            }
          }
        }
      }
    }
  }
}
```

The `operationId` field (e.g., `PostEntitiesAlertsV1`) is what you pass to the `generate operation` command.

#### Generate Collection

Generate Go client code for all operations with a specific tag:

```bash
# Generate all operations in a collection
generate collection Alerts
```

Collections group related operations together by their Swagger tags.

**Example Collection/Tag Structure in Swagger Spec:**

Operations are grouped into collections using the `tags` field. Here's how operations are tagged:

```json
{
  "paths": {
    "/alerts/entities/alerts/v1": {
      "post": {
        "operationId": "PostEntitiesAlertsV1",
        "tags": ["Alerts"],
        "summary": "Retrieves all Alerts given their ids."
      }
    },
    "/alerts/entities/alerts/v2": {
      "post": {
        "operationId": "GetV2",
        "tags": ["Alerts"],
        "summary": "Retrieves all Alerts given their composite ids."
      },
      "patch": {
        "operationId": "PatchEntitiesAlertsV2",
        "tags": ["Alerts"],
        "summary": "Perform actions on Alerts identified by composite ids."
      }
    }
  }
}
```

The tag name (e.g., `Alerts`) is what you pass to the `generate collection` command. This will generate client code for all operations that have that tag.

#### Inspect Model

Analyze the dependencies and impact of a specific model:

```bash
# Inspect what depends on a model
generate inspect domain.IOACounts

# Verbose output
generate inspect domain.IOACounts --verbose
```

This performs reverse dependency analysis to show:
- All models that directly or indirectly reference the specified model
- All operations that use any of these models

### Common Options

All commands support these flags:

- `--spec-file`, `-f`: Path to swagger specification file (default: `specs/swagger-stripped-oauth.json`)
- `--output-dir`, `-t`: Output directory for generated code (default: `falcon`)
- `--skip-spec-gen`: Skip regenerating the swagger spec, use existing spec file
- `--skip-validation`: Skip validation during swagger generation (default: true)
- `--verbose`, `-v`: Enable verbose output

### Limitations

**Important: go-swagger Client File Updates**

When generating specific collections, operations, or endpoints, the generate tool will update [falcon/client/crowd_strike_api_specification_client.go](falcon/client/crowd_strike_api_specification_client.go) and remove references to collections that were not included in the generate command. This is a limitation of go-swagger itself.

**Example:**

```bash
# Generate only the prevention-policies collection
generate collection prevention-policies
```

This will:
- ✅ Generate/update the `prevention-policies` client and models correctly
- ⚠️ Remove other collection references from `crowd_strike_api_specification_client.go`

**How to handle this:**

When reviewing changes after running a selective generate command, **discard the deletions** from `crowd_strike_api_specification_client.go` for collections you want to keep. Only keep the additions/updates for the collection you generated.

This limitation applies to:
- `generate collection`
- `generate operation`
- `generate endpoint`

For the `generate model` command, this issue does not apply as it only generates model structs without updating the main client file.
