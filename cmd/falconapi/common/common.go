package common

import (
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	// Commands holds the cobra.Commands to present to the user, including
	// parent if not a child of "root"
	Commands  []CliCommand
	APIClient *client.CrowdStrikeAPISpecification
)

type CliCommand struct {
	Command *cobra.Command
	Parent  *cobra.Command
}

func AllCommands(commands CliCommand) []CliCommand {
	return append(Commands, commands)
}

// SubCommandExists returns an error if no sub command is provided
func SubCommandExists(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		suggestions := cmd.SuggestionsFor(args[0])
		if len(suggestions) == 0 {
			return errors.Errorf("unrecognized command `%[1]s %[2]s`\nTry '%[1]s --help' for more information.", cmd.CommandPath(), args[0])
		}
		return errors.Errorf("unrecognized command `%[1]s %[2]s`\n\nDid you mean this?\n\t%[3]s\n\nTry '%[1]s --help' for more information.", cmd.CommandPath(), args[0], strings.Join(suggestions, "\n\t"))
	}
	return errors.Errorf("missing command '%[1]s COMMAND'\nTry '%[1]s --help' for more information.", cmd.CommandPath())
}
