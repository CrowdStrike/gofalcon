package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1; default taken from FALCON_CLOUD)")
	aidString := flag.String("aids", os.Getenv("FALCON_AGENT_IDS"), "Comma-delimited string of Falcon agent IDs on which to run the command (default taken from FALCON_AGENT_IDS)")
	cmd := flag.String("cmd", os.Getenv("FALCON_RTR_COMMAND"), "RTR command to run on the specified agent. (default taken from FALCON_RTR_COMMAND)")
	timeoutDurationString := flag.String("timeout", os.Getenv("FALCON_RTR_BATCH_TIMEOUT"), "Timeout in time.Duration format (e.g., '10s, 3m') for the entire batch of RTR commands (default taken from FALCON_RTR_BATCH_TIMEOUT)")
	hostTimeoutDurationString := flag.String("host-timeout", os.Getenv("FALCON_RTR_BATCH_HOST_TIMEOUT"), "Timeout in time.Duration format (e.g., '10s, 3m') for an individual command within the batch (default taken from FALCON_RTR_BATCH_HOST_TIMEOUT)")

	flag.Parse()
	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}
	if *aidString == "" {
		*aidString = falcon_util.PromptUser(`Missing FALCON_AGENT_IDS. Please provide the ID of the agent you would like to communicate with.
Falcon agent IDs`)
	}
	if *cmd == "" {
		*cmd = falcon_util.PromptUser(`Missing FALCON_RTR_COMMAND. Please provide the RTR command you would like to run. See https://falcon.crowdstrike.com/documentation/71/real-time-response-and-network-containment#rtr_commands for a list of RTR Read Only Analyst commands.
Falcon RTR command`)
	}
	if *timeoutDurationString == "" {
		*timeoutDurationString = falcon_util.PromptUser(`Missing FALCON_RTR_BATCH_TIMEOUT. Please provide the timeout in time.Duration format (10s, 2m) for the entire batch.
Falcon RTR batch timeout`)
	}
	if *hostTimeoutDurationString == "" {
		*hostTimeoutDurationString = falcon_util.PromptUser(`Missing FALCON_RTR_BATCH_HOST_TIMEOUT. Please provide the timeout in time.Duration format (10s, 2m) for east host session in the batch.
Falcon RTR host timeout`)
	}
	aids := strings.Split(falcon_util.DerefString(aidString), ",")
	timeoutDuration, err := time.ParseDuration(*timeoutDurationString)
	if err != nil {
		panic(err)
	}
	hostTimeoutDuration, err := time.ParseDuration(*hostTimeoutDurationString)
	if err != nil {
		panic(err)
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

	session, err := client.NewBatchSession(context.Background(), nil, &timeoutDuration, hostTimeoutDuration, aids, nil, false)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	result, err := client.BatchCmd(context.Background(), nil, &timeoutDuration, hostTimeoutDuration, strings.Split(*cmd, " ")[0], *session.BatchID, *cmd, nil)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}

	json, _ := falcon_util.PrettyJson(result)
	fmt.Println(json)
}
