package generator

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Config holds configuration for model generation
type Config struct {
	ModelNames         []string
	ModelName          string // For inspect mode - single model to analyze
	OperationID        string
	EndpointPath       string
	TagName            string
	SpecFile           string
	OutputDir          string
	SkipSpecGen        bool
	SkipValidation     bool
	Verbose            bool
	GenerateOperation  bool
	GenerateEndpoint   bool
	GenerateCollection bool
	InspectMode        bool // For reverse dependency analysis
}

// OpenAPISpec represents the structure of an OpenAPI/Swagger specification
type OpenAPISpec struct {
	Paths       map[string]PathItem    `json:"paths"`
	Components  *Components            `json:"components"`
	Definitions map[string]interface{} `json:"definitions"` // For Swagger 2.0
}

// PathItem represents a single path in the OpenAPI spec
type PathItem struct {
	Get    *Operation `json:"get"`
	Post   *Operation `json:"post"`
	Put    *Operation `json:"put"`
	Delete *Operation `json:"delete"`
	Patch  *Operation `json:"patch"`
}

// Operation represents an operation in the OpenAPI spec
type Operation struct {
	OperationID string              `json:"operationId"`
	Tags        []string            `json:"tags"`
	Parameters  []Parameter         `json:"parameters"`
	RequestBody *RequestBody        `json:"requestBody"`
	Responses   map[string]Response `json:"responses"`
}

// Parameter represents a parameter in an operation
type Parameter struct {
	Schema *Schema `json:"schema"`
}

// RequestBody represents a request body in an operation
type RequestBody struct {
	Content map[string]MediaType `json:"content"`
}

// MediaType represents a media type in request/response
type MediaType struct {
	Schema *Schema `json:"schema"`
}

// Response represents a response in an operation
type Response struct {
	Content map[string]MediaType `json:"content"` // OpenAPI 3.0 format
	Schema  *Schema              `json:"schema"`  // Swagger 2.0 format
}

// Schema represents a JSON schema
type Schema struct {
	Ref        string             `json:"$ref"`
	Type       string             `json:"type"`
	Items      *Schema            `json:"items"`
	Properties map[string]*Schema `json:"properties"`
	AllOf      []*Schema          `json:"allOf"`
	OneOf      []*Schema          `json:"oneOf"`
	AnyOf      []*Schema          `json:"anyOf"`
}

// Components represents the components section of OpenAPI 3.0
type Components struct {
	Schemas map[string]*Schema `json:"schemas"`
}

// Generator handles the model generation workflow
type Generator struct {
	config *Config
}

// New creates a new Generator instance
func New(config *Config) *Generator {
	return &Generator{config: config}
}

// Generate runs the complete model generation workflow
func (g *Generator) Generate() error {
	if g.config.Verbose {
		fmt.Printf("Generating swagger models for: %s\n\n", strings.Join(g.config.ModelNames, ","))
	}

	if !g.config.SkipSpecGen {
		if err := g.generateSpec(); err != nil {
			return fmt.Errorf("spec generation failed: %w", err)
		}
	}

	if err := g.verifySpecFile(); err != nil {
		return fmt.Errorf("spec verification failed: %w", err)
	}

	if err := g.generateModels(); err != nil {
		return fmt.Errorf("model generation failed: %w", err)
	}

	if g.config.Verbose {
		fmt.Println("\nModel generation completed successfully!")
	}

	return nil
}

// generateSpec runs 'make spec' to generate the swagger specification
func (g *Generator) generateSpec() error {
	if g.config.Verbose {
		fmt.Println("Regenerating swagger spec...")
	}

	cmd := exec.Command("make", "spec")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make spec command failed: %w", err)
	}

	if g.config.Verbose {
		fmt.Println("Spec generation completed")
		fmt.Println()
	}

	return nil
}

// verifySpecFile checks if the swagger spec file exists
func (g *Generator) verifySpecFile() error {
	if _, err := os.Stat(g.config.SpecFile); os.IsNotExist(err) {
		return fmt.Errorf("swagger spec file not found: %s", g.config.SpecFile)
	}
	return nil
}

// generateModels runs swagger generate model command
func (g *Generator) generateModels() error {
	if g.config.Verbose {
		fmt.Println("Generating models...")
	}

	modelNames := strings.Join(g.config.ModelNames, ",")
	args := []string{"generate", "model", "-f", g.config.SpecFile, "-t", g.config.OutputDir, "-n", modelNames}

	if g.config.SkipValidation {
		args = append(args, "--skip-validation")
	}

	if g.config.Verbose {
		fmt.Printf("Command: swagger %s\n\n", strings.Join(args, " "))
	}

	return g.executeSwaggerCommand(args)
}

// executeSwaggerCommand executes a swagger command with the given arguments
func (g *Generator) executeSwaggerCommand(args []string) error {
	cmd := exec.Command("swagger", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("swagger command failed: %w", err)
	}

	return nil
}
