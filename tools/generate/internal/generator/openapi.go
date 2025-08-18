package generator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

// FindModelsForOperation analyzes an OpenAPI spec and finds all models referenced by a specific operation
func (g *Generator) FindModelsForOperation(specFile, operationID string) ([]string, error) {
	data, err := ioutil.ReadFile(specFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	var spec OpenAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse spec file: %w", err)
	}

	operation := g.findOperation(&spec, operationID)
	if operation == nil {
		return nil, fmt.Errorf("operation '%s' not found in spec", operationID)
	}

	visited := make(map[string]bool)
	models := make(map[string]bool)

	g.analyzeOperation(operation, &spec, models, visited)

	var result []string
	for model := range models {
		result = append(result, model)
	}

	return result, nil
}

// findOperation searches for an operation by operationId in the spec
func (g *Generator) findOperation(spec *OpenAPISpec, operationID string) *Operation {
	for _, pathItem := range spec.Paths {
		operations := []*Operation{
			pathItem.Get,
			pathItem.Post,
			pathItem.Put,
			pathItem.Delete,
			pathItem.Patch,
		}

		for _, op := range operations {
			if op != nil && op.OperationID == operationID {
				return op
			}
		}
	}
	return nil
}

// analyzeOperation recursively finds all models referenced by an operation
func (g *Generator) analyzeOperation(operation *Operation, spec *OpenAPISpec, models map[string]bool, visited map[string]bool) {
	if g.config.Verbose {
		fmt.Printf("Analyzing operation with %d parameters and %d responses\n", len(operation.Parameters), len(operation.Responses))
	}

	for i, param := range operation.Parameters {
		if g.config.Verbose {
			fmt.Printf("  Parameter %d: schema=%v\n", i, param.Schema != nil)
		}
		if param.Schema != nil {
			if g.config.Verbose && param.Schema.Ref != "" {
				fmt.Printf("    Found parameter ref: %s\n", param.Schema.Ref)
			}
			g.analyzeSchema(param.Schema, spec, models, visited)
		}
	}

	if operation.RequestBody != nil {
		for _, mediaType := range operation.RequestBody.Content {
			if mediaType.Schema != nil {
				g.analyzeSchema(mediaType.Schema, spec, models, visited)
			}
		}
	}

	for statusCode, response := range operation.Responses {
		if g.config.Verbose {
			fmt.Printf("  Response %s: content=%d items, schema=%v\n", statusCode, len(response.Content), response.Schema != nil)
		}

		for _, mediaType := range response.Content {
			if mediaType.Schema != nil {
				g.analyzeSchema(mediaType.Schema, spec, models, visited)
			}
		}

		if response.Schema != nil {
			if g.config.Verbose && response.Schema.Ref != "" {
				fmt.Printf("    Found response ref: %s\n", response.Schema.Ref)
			}
			g.analyzeSchema(response.Schema, spec, models, visited)
		}
	}
}

// analyzeSchema recursively analyzes a schema and finds all referenced models
func (g *Generator) analyzeSchema(schema *Schema, spec *OpenAPISpec, models map[string]bool, visited map[string]bool) {
	if schema == nil {
		return
	}

	// Handle $ref
	if schema.Ref != "" {
		modelName := g.extractModelName(schema.Ref)
		if modelName != "" && !visited[modelName] {
			visited[modelName] = true
			models[modelName] = true

			// Find the referenced schema and analyze it recursively
			referencedSchema := g.findSchemaByRef(spec, schema.Ref)
			if referencedSchema != nil {
				g.analyzeSchema(referencedSchema, spec, models, visited)
			}
		}
		return
	}

	// Handle array items
	if schema.Items != nil {
		g.analyzeSchema(schema.Items, spec, models, visited)
	}

	// Handle object properties
	for _, propSchema := range schema.Properties {
		g.analyzeSchema(propSchema, spec, models, visited)
	}

	// Handle composition (allOf, oneOf, anyOf)
	for _, subSchema := range schema.AllOf {
		g.analyzeSchema(subSchema, spec, models, visited)
	}
	for _, subSchema := range schema.OneOf {
		g.analyzeSchema(subSchema, spec, models, visited)
	}
	for _, subSchema := range schema.AnyOf {
		g.analyzeSchema(subSchema, spec, models, visited)
	}
}

// extractModelName extracts the model name from a $ref string
func (g *Generator) extractModelName(ref string) string {
	// Handle OpenAPI 3.0 format: #/components/schemas/ModelName
	if strings.HasPrefix(ref, "#/components/schemas/") {
		return strings.TrimPrefix(ref, "#/components/schemas/")
	}

	// Handle Swagger 2.0 format: #/definitions/ModelName
	if strings.HasPrefix(ref, "#/definitions/") {
		return strings.TrimPrefix(ref, "#/definitions/")
	}

	return ""
}

// findSchemaByRef finds a schema definition by its $ref path
func (g *Generator) findSchemaByRef(spec *OpenAPISpec, ref string) *Schema {
	modelName := g.extractModelName(ref)
	if modelName == "" {
		return nil
	}

	// Check OpenAPI 3.0 components/schemas
	if spec.Components != nil && spec.Components.Schemas != nil {
		if schema, exists := spec.Components.Schemas[modelName]; exists {
			return schema
		}
	}

	// Check Swagger 2.0 definitions
	if spec.Definitions != nil {
		if def, exists := spec.Definitions[modelName]; exists {
			// Convert interface{} to Schema (simplified)
			data, err := json.Marshal(def)
			if err != nil {
				return nil
			}
			var schema Schema
			if err := json.Unmarshal(data, &schema); err != nil {
				return nil
			}
			return &schema
		}
	}

	return nil
}

// FindOperationsForEndpoint finds all operations on a specific endpoint path
func (g *Generator) FindOperationsForEndpoint(specFile, endpointPath string) ([]string, error) {
	data, err := ioutil.ReadFile(specFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	var spec OpenAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse spec file: %w", err)
	}

	pathItem, exists := spec.Paths[endpointPath]
	if !exists {
		return nil, fmt.Errorf("endpoint path '%s' not found in spec", endpointPath)
	}

	var operations []string

	if pathItem.Get != nil && pathItem.Get.OperationID != "" {
		operations = append(operations, pathItem.Get.OperationID)
	}
	if pathItem.Post != nil && pathItem.Post.OperationID != "" {
		operations = append(operations, pathItem.Post.OperationID)
	}
	if pathItem.Put != nil && pathItem.Put.OperationID != "" {
		operations = append(operations, pathItem.Put.OperationID)
	}
	if pathItem.Delete != nil && pathItem.Delete.OperationID != "" {
		operations = append(operations, pathItem.Delete.OperationID)
	}
	if pathItem.Patch != nil && pathItem.Patch.OperationID != "" {
		operations = append(operations, pathItem.Patch.OperationID)
	}

	if len(operations) == 0 {
		return nil, fmt.Errorf("no operations found for endpoint path '%s'", endpointPath)
	}

	return operations, nil
}

// FindModelsForOperations finds all models referenced by multiple operations
func (g *Generator) FindModelsForOperations(specFile string, operationIDs []string) ([]string, error) {
	allModels := make(map[string]bool)

	// Find models for each operation and combine them
	for _, operationID := range operationIDs {
		models, err := g.FindModelsForOperation(specFile, operationID)
		if err != nil {
			return nil, fmt.Errorf("failed to find models for operation '%s': %w", operationID, err)
		}

		// Add models to the combined set
		for _, model := range models {
			allModels[model] = true
		}
	}

	// Convert map to slice
	var result []string
	for model := range allModels {
		result = append(result, model)
	}

	return result, nil
}

// GenerateOperation generates a client for a specific operation and its models
func (g *Generator) GenerateOperation() error {
	if g.config.Verbose {
		fmt.Printf("Generating operation: %s\n", g.config.OperationID)
	}

	// Step 1: Generate swagger spec (unless skipped)
	if !g.config.SkipSpecGen {
		if err := g.generateSpec(); err != nil {
			return fmt.Errorf("spec generation failed: %w", err)
		}
	}

	// Step 2: Verify spec file exists
	if err := g.verifySpecFile(); err != nil {
		return fmt.Errorf("spec verification failed: %w", err)
	}

	// Step 3: Find all models referenced by the operation
	models, err := g.FindModelsForOperation(g.config.SpecFile, g.config.OperationID)
	if err != nil {
		return fmt.Errorf("failed to find models for operation: %w", err)
	}

	if g.config.Verbose {
		fmt.Printf("Found %d models: %s\n", len(models), strings.Join(models, ", "))
	}

	// Build swagger generate client command
	args := []string{"generate", "client", "-f", g.config.SpecFile, "-t", g.config.OutputDir, "--operation", g.config.OperationID}

	if g.config.SkipValidation {
		args = append(args, "--skip-validation")
	}

	// Add models as comma-separated list with --model flag
	for _, model := range models {
		args = append(args, "--model", model)
	}

	if g.config.Verbose {
		fmt.Printf("Command: swagger %s\n\n", strings.Join(args, " "))
	}

	// Execute the command
	return g.executeSwaggerCommand(args)
}

// FindOperationsForTag finds all operations tagged with a specific tag/collection name
func (g *Generator) FindOperationsForTag(specFile, tagName string) ([]string, error) {
	// Read and parse the OpenAPI spec
	data, err := ioutil.ReadFile(specFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	var spec OpenAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse spec file: %w", err)
	}

	var operations []string

	// Search through all paths and operations
	for _, pathItem := range spec.Paths {
		pathOperations := []*Operation{
			pathItem.Get,
			pathItem.Post,
			pathItem.Put,
			pathItem.Delete,
			pathItem.Patch,
		}

		for _, op := range pathOperations {
			if op != nil && op.OperationID != "" {
				// Check if the operation has the specified tag
				for _, tag := range op.Tags {
					if tag == tagName {
						operations = append(operations, op.OperationID)
						break // Only add once per operation
					}
				}
			}
		}
	}

	if len(operations) == 0 {
		return nil, fmt.Errorf("no operations found for tag '%s'", tagName)
	}

	return operations, nil
}

// GenerateCollection generates a client for all operations with a specific tag and their models
func (g *Generator) GenerateCollection() error {
	if g.config.Verbose {
		fmt.Printf("Generating collection: %s\n", g.config.TagName)
	}

	// Step 1: Generate swagger spec (unless skipped)
	if !g.config.SkipSpecGen {
		if err := g.generateSpec(); err != nil {
			return fmt.Errorf("spec generation failed: %w", err)
		}
	}

	// Step 2: Verify spec file exists
	if err := g.verifySpecFile(); err != nil {
		return fmt.Errorf("spec verification failed: %w", err)
	}

	// Step 3: Find all operations with the specified tag
	operations, err := g.FindOperationsForTag(g.config.SpecFile, g.config.TagName)
	if err != nil {
		return fmt.Errorf("failed to find operations for tag: %w", err)
	}

	if g.config.Verbose {
		fmt.Printf("Found %d operations: %s\n", len(operations), strings.Join(operations, ", "))
	}

	// Step 4: Find all models referenced by all operations
	models, err := g.FindModelsForOperations(g.config.SpecFile, operations)
	if err != nil {
		return fmt.Errorf("failed to find models for operations: %w", err)
	}

	if g.config.Verbose {
		fmt.Printf("Found %d models: %s\n", len(models), strings.Join(models, ", "))
	}

	// Build swagger generate client command with multiple operations
	args := []string{"generate", "client", "-f", g.config.SpecFile, "-t", g.config.OutputDir}

	// Add all operations
	for _, operation := range operations {
		args = append(args, "--operation", operation)
	}

	if g.config.SkipValidation {
		args = append(args, "--skip-validation")
	}

	// Add models
	for _, model := range models {
		args = append(args, "--model", model)
	}

	if g.config.Verbose {
		fmt.Printf("Command: swagger %s\n\n", strings.Join(args, " "))
	}

	// Execute the command
	return g.executeSwaggerCommand(args)
}

// GenerateEndpoint generates a client for all operations on a specific endpoint and their models
func (g *Generator) GenerateEndpoint() error {
	if g.config.Verbose {
		fmt.Printf("Generating endpoint: %s\n", g.config.EndpointPath)
	}

	// Step 1: Generate swagger spec (unless skipped)
	if !g.config.SkipSpecGen {
		if err := g.generateSpec(); err != nil {
			return fmt.Errorf("spec generation failed: %w", err)
		}
	}

	// Step 2: Verify spec file exists
	if err := g.verifySpecFile(); err != nil {
		return fmt.Errorf("spec verification failed: %w", err)
	}

	// Step 3: Find all operations on the endpoint
	operations, err := g.FindOperationsForEndpoint(g.config.SpecFile, g.config.EndpointPath)
	if err != nil {
		return fmt.Errorf("failed to find operations for endpoint: %w", err)
	}

	if g.config.Verbose {
		fmt.Printf("Found %d operations: %s\n", len(operations), strings.Join(operations, ", "))
	}

	// Step 4: Find all models referenced by all operations
	models, err := g.FindModelsForOperations(g.config.SpecFile, operations)
	if err != nil {
		return fmt.Errorf("failed to find models for operations: %w", err)
	}

	if g.config.Verbose {
		fmt.Printf("Found %d models: %s\n", len(models), strings.Join(models, ", "))
	}

	// Build swagger generate client command with multiple operations
	args := []string{"generate", "client", "-f", g.config.SpecFile, "-t", g.config.OutputDir}

	// Add all operations
	for _, operation := range operations {
		args = append(args, "--operation", operation)
	}

	if g.config.SkipValidation {
		args = append(args, "--skip-validation")
	}

	// Add models
	for _, model := range models {
		args = append(args, "--model", model)
	}

	if g.config.Verbose {
		fmt.Printf("Command: swagger %s\n\n", strings.Join(args, " "))
	}

	// Execute the command
	return g.executeSwaggerCommand(args)
}
