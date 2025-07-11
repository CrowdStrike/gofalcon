# Contributing to gofalcon

## Prerequisites

- **[Go](https://golang.org/) 1.23.0+**
- **[jq](https://jqlang.github.io/jq/) >= 1.7.1+**
- **go-swagger:**
  ```bash
  go install github.com/ffalor/go-swagger/cmd/swagger@latest
  ```
- **Access to CrowdStrike Falcon console**

## Development Setup

1. Fork and clone the repository
2. Install the prerequisites above
3. You're ready to contribute!

## SDK Regeneration Process

The gofalcon SDK is generated from CrowdStrike's OpenAPI specifications. To regenerate:

1. **Obtain the latest swagger.json:**
   - Login to your CrowdStrike Falcon console
   - Navigate to: `https://assets.falcon.crowdstrike.com/support/api/swagger.json`
   - Save the file as `specs/swagger.json` in your local repository

   **Alternative regions:**
   
   The US-1 region is prefered, but you can use the swagger from the following regions also if you do not have access to US-1.
   - US-2: `https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-mav.json`
   - EU-1: `https://assets.falcon.eu-1.crowdstrike.com/support/api/swagger-lion.json`

2. **Regenerate the SDK:**
   ```bash
   make clean-generate
   ```

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
   - All the code in `falcon/client/` and `falcon/models/` directories is generated from this process

## Building

After making changes:
```bash
make build
```

## Submitting Changes

1. Create a feature branch
2. Make your changes
3. Test your changes with `make build`
4. Submit a pull request with a clear description
