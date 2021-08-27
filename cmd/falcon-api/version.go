package main

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/cmd/falcon-api/common"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/spf13/cobra"
)

var (
	// Command: falcon-api _version_
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "version for falcon-api",
		Long:  "version for falcon-api",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("falcon-api version %s\n", falcon.Version.String())
			return nil
		},
	}
)

func init() {
	common.Commands = common.AllCommands(common.CliCommand{
		Command: versionCmd,
	})
}
