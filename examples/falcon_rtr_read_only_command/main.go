package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1; default taken from FALCON_CLOUD)")
	aid := flag.String("aid", os.Getenv("FALCON_AGENT_ID"), "Falcon agent ID on which to run the command (default taken from FALCON_AGENT_ID)")
	cmd := flag.String("cmd", os.Getenv("FALCON_RTR_COMMAND"), "RTR command to run on the specified agent. (default taken from FALCON_RTR_COMMAND)")

	flag.Parse()
	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}
	if *aid == "" {
		*aid = falcon_util.PromptUser(`Missing FALCON_AGENT_ID. Please provide the ID of the agent you would like to communicate with.
Falcon agent ID`)
	}
	if *cmd == "" {
		*cmd = falcon_util.PromptUser(`Missing FALCON_RTR_COMMAND. Please provide the RTR command you would like to run. See https://falcon.crowdstrike.com/documentation/71/real-time-response-and-network-containment#rtr_commands for a list of RTR Read Only Analyst commands.
Falcon RTR command`)
	}

	client, err := falcon.NewRTR(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	session, err := client.NewSession(context.Background(), *aid)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	result, err := session.ExecuteAndWait(context.Background(), strings.Split(*cmd, " ")[0], *cmd)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}

	json, _ := falcon_util.PrettyJson(result)
	fmt.Println(json)
}
