package falcon_util

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
)

func PromptUser(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	s, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(s)
}

func CliClient(opts falcon.ApiConfig) *client.CrowdStrikeAPISpecification {
	client, err := falcon.NewClient(&opts)
	if err != nil {
		panic(err)
	}

	return client
}
