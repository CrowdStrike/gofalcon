package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/cmd/falcon-api/common"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// HelpTemplate is the help template
// This uses the short and long options.
// command should not use this.
const helpTemplate = `{{.Short}}
Description:
  {{.Long}}
{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

// UsageTemplate is the usage template
// This blocks the displaying of the global options. The main
// command should not use this.
const usageTemplate = `Usage:{{if (and .Runnable (not .HasAvailableSubCommands))}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.UseLine}} [command]{{end}}{{if gt (len .Aliases) 0}}
Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}
Examples:
  {{.Example}}{{end}}{{if .HasAvailableSubCommands}}
Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}
Global Options:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableLocalFlags}}
Options:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}
{{end}}
`

// Opts struct to get falcon cloud
type Opts struct {
	Cloud string
}

var (
	gopts   falcon.ApiConfig
	opts    Opts
	rootCmd = &cobra.Command{
		Use:                   "falcon-api",
		Short:                 "falcon-api - Creating Dockerfiles using Go templating",
		Long:                  `A tool to create multiple Dockerfiles using Go-style templating`,
		SilenceUsage:          false,
		SilenceErrors:         true,
		TraverseChildren:      true,
		DisableFlagsInUseLine: true,
		Version:               falcon.Version.String(),
		RunE:                  common.SubCommandExists,
		PersistentPreRunE:     persistentPreRunE,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootFlags(rootCmd)
}

func initConfig() {
	// For anything related to Cobra initializing
}

func persistentPreRunE(cmd *cobra.Command, args []string) error {

	if cmd.Name() == "help" || cmd.Name() == "version" || cmd.HasSubCommands() {
		return nil
	}

	if gopts.ClientId == "" {
		gopts.ClientId = falcon_util.PromptUser("Missing FALCON_CLIENT_ID environment variable.\n\nPlease provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform.\nEstablishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.\n\nFalcon Client ID")
	}
	if gopts.ClientSecret == "" {
		gopts.ClientSecret = falcon_util.PromptUser("Missing FALCON_CLIENT_SECRET environment variable.\n\nPlease provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform.\nEstablishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.\n\nFalcon Client Secret")
	}

	gopts.Cloud = falcon.Cloud(opts.Cloud)
	common.APIClient = falcon_util.CliClient(gopts)

	// Until there are new contexts we set the context here
	gopts.Context = context.Background()

	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootFlags(cmd *cobra.Command) {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("falcon")
	viper.SetDefault("cloud", "us-1")

	pflags := cmd.PersistentFlags()
	pflags.StringVar(&gopts.ClientId, "client-id", viper.GetString("client_id"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	pflags.StringVar(&gopts.ClientSecret, "client-secret", viper.GetString("client_secret"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	pflags.StringVar(&gopts.MemberCID, "member-cid", viper.GetString("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	pflags.StringVar(&opts.Cloud, "cloud", viper.GetString("cloud"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
}
