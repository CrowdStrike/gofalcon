package main

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/cmd/falconapi/common"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/spf13/cobra"
)

var (
	// Command: falconapi _version_
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "version for falconapi",
		Long:  "version for falconapi",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("falconapi version %s\n", falcon.Version.String())
			return nil
		},
	}
)

func init() {
	common.Commands = common.AllCommands(common.CliCommand{
		Command: versionCmd,
	})
}
