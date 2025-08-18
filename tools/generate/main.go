package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/tools/generate/internal/generator"
	"github.com/spf13/cobra"
)

var (
	verbose        bool
	specFile       string
	outputDir      string
	skipSpecGen    bool
	skipValidation bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "generate",
	Short: "A versatile code generation tool for the GoFalcon SDK",
	Long: `Generate is a versatile code generation tool for the GoFalcon SDK.
It provides various subcommands for different types of code generation tasks.`,
}

// modelCmd represents the model command
var modelCmd = &cobra.Command{
	Use:   "model [model-names...]",
	Short: "Generate Go model structs from Swagger specifications",
	Long: `Generate Go model structs from Swagger/OpenAPI specifications.

Takes one or more model names as arguments and generates the corresponding 
Go structs using the swagger generate model command.`,
	Example: `  # Generate a single model
  generate model DomainIOARule

  # Generate multiple models
  generate model DomainIOARule,DomainAPIError,DomainHost

  # Generate models with custom spec file
  generate model DomainIOARule --spec-file custom-swagger.json

  # Skip spec generation (use existing spec file)
  generate model DomainIOARule --skip-spec-gen`,
	Args: cobra.MinimumNArgs(1),
	RunE: runModelGeneration,
}

// endpointCmd represents the endpoint command
var endpointCmd = &cobra.Command{
	Use:   "endpoint [endpoint-path]",
	Short: "Generate Go client code for all operations on a specific endpoint with minimal models",
	Long: `Generate Go client code for all operations on a specific endpoint with only the models used by those operations.

This command analyzes the Swagger specification to find all operations (GET, POST, PUT, DELETE, PATCH) 
on the specified endpoint path and generates client code for all of them along with only the models 
they reference, resulting in a more focused code generation.`,
	Example: `  # Generate client for all operations on an endpoint
  generate endpoint /sensor-visibility-exclusions/entities/sv-exclusions/v1

  # Generate with custom spec file
  generate endpoint /sensor-visibility-exclusions/entities/sv-exclusions/v1 --spec-file custom-swagger.json

  # Skip spec generation (use existing spec file)
  generate endpoint /sensor-visibility-exclusions/entities/sv-exclusions/v1 --skip-spec-gen`,
	Args: cobra.ExactArgs(1),
	RunE: runEndpointGeneration,
}

// operationCmd represents the operation command
var operationCmd = &cobra.Command{
	Use:   "operation [operation-id]",
	Short: "Generate Go client code for a specific operation with minimal models",
	Long: `Generate Go client code for a specific operation with only the models used by that operation.

This command analyzes the Swagger specification to find the specified operation by its operationId 
and generates client code for it along with only the models it references, resulting in a more 
focused code generation.

The operation ID is the unique identifier for an operation in the Swagger specification.`,
	Example: `  # Generate client for a specific operation
  generate operation GetSensorVisibilityExclusionsV1

  # Generate with custom spec file
  generate operation GetSensorVisibilityExclusionsV1 --spec-file custom-swagger.json

  # Skip spec generation (use existing spec file)
  generate operation GetSensorVisibilityExclusionsV1 --skip-spec-gen`,
	Args: cobra.ExactArgs(1),
	RunE: runOperationGeneration,
}

// collectionCmd represents the collection command
var collectionCmd = &cobra.Command{
	Use:   "collection [tag-name]",
	Short: "Generate Go client code for all operations with a specific tag/collection with minimal models",
	Long: `Generate Go client code for all operations tagged with the specified collection name and only the models they reference.

This command analyzes the Swagger specification to find all operations with the specified tag 
and generates client code for all of them along with only the models they reference, 
resulting in a more focused code generation.

A collection/tag groups related operations together. For example, the "sensor-visibility-exclusions" 
tag groups all operations related to sensor visibility exclusions.`,
	Example: `  # Generate client for all operations in a collection
  generate collection sensor-visibility-exclusions

  # Generate with custom spec file
  generate collection sensor-visibility-exclusions --spec-file custom-swagger.json

  # Skip spec generation (use existing spec file)
  generate collection sensor-visibility-exclusions --skip-spec-gen`,
	Args: cobra.ExactArgs(1),
	RunE: runCollectionGeneration,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&specFile, "spec-file", "f", "specs/swagger-stripped-oauth.json", "Path to swagger specification file")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "t", "falcon", "Output directory for generated code")
	rootCmd.PersistentFlags().BoolVar(&skipSpecGen, "skip-spec-gen", false, "Skip regenerating the swagger spec (use existing spec file)")
	rootCmd.PersistentFlags().BoolVar(&skipValidation, "skip-validation", true, "Skip validation during swagger generation")

	rootCmd.AddCommand(modelCmd)
	rootCmd.AddCommand(endpointCmd)
	rootCmd.AddCommand(operationCmd)
	rootCmd.AddCommand(collectionCmd)
}

func runModelGeneration(cmd *cobra.Command, args []string) error {
	var modelNames []string
	for _, arg := range args {
		if len(args) == 1 && len(arg) > 0 {
			models := splitModelNames(arg)
			modelNames = append(modelNames, models...)
		} else {
			modelNames = append(modelNames, arg)
		}
	}

	if len(modelNames) == 0 {
		return fmt.Errorf("no model names provided")
	}

	config := &generator.Config{
		ModelNames:     modelNames,
		SpecFile:       specFile,
		OutputDir:      outputDir,
		SkipSpecGen:    skipSpecGen,
		SkipValidation: skipValidation,
		Verbose:        verbose,
	}

	gen := generator.New(config)
	return gen.Generate()
}

func runEndpointGeneration(cmd *cobra.Command, args []string) error {
	endpointPath := args[0]

	if endpointPath == "" {
		return fmt.Errorf("endpoint path cannot be empty")
	}

	config := &generator.Config{
		EndpointPath:     endpointPath,
		SpecFile:         specFile,
		OutputDir:        outputDir,
		SkipSpecGen:      skipSpecGen,
		SkipValidation:   skipValidation,
		Verbose:          verbose,
		GenerateEndpoint: true,
	}

	gen := generator.New(config)
	return gen.GenerateEndpoint()
}

func runOperationGeneration(cmd *cobra.Command, args []string) error {
	operationID := args[0]

	if operationID == "" {
		return fmt.Errorf("operation ID cannot be empty")
	}

	config := &generator.Config{
		OperationID:       operationID,
		SpecFile:          specFile,
		OutputDir:         outputDir,
		SkipSpecGen:       skipSpecGen,
		SkipValidation:    skipValidation,
		Verbose:           verbose,
		GenerateOperation: true,
	}

	gen := generator.New(config)
	return gen.GenerateOperation()
}

func runCollectionGeneration(cmd *cobra.Command, args []string) error {
	tagName := args[0]

	if tagName == "" {
		return fmt.Errorf("tag name cannot be empty")
	}

	config := &generator.Config{
		TagName:            tagName,
		SpecFile:           specFile,
		OutputDir:          outputDir,
		SkipSpecGen:        skipSpecGen,
		SkipValidation:     skipValidation,
		Verbose:            verbose,
		GenerateCollection: true,
	}

	gen := generator.New(config)
	return gen.GenerateCollection()
}

// splitModelNames splits a comma-separated string of model names
func splitModelNames(input string) []string {
	var names []string
	for _, name := range strings.Split(input, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
