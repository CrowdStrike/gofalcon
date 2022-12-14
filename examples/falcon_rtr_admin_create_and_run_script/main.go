package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/go-openapi/runtime"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1; default taken from FALCON_CLOUD)")
	aid := flag.String("aid", os.Getenv("FALCON_AGENT_ID"), "Falcon agent ID on which to run the custom script (default taken from FALCON_AGENT_ID)")
	permType := flag.String("permtype", "group", "Permission type (private, group, or public; default is group, which makes the script usable to all RTR Admins)")
	platformString := flag.String("platforms", "linux", "The platform(s) the file supports. If specified, can be one or more of [windows, mac, linux] (default for this script is linux)")
	script := flag.String("script", "examples/falcon_rtr_admin_create_and_run_script/examplescript.sh", "Relative path to the script to upload (defaults to the script included in this example, assuming cwd is the project root)")
	name := flag.String("name", "examplescript.sh", "Name to give to the uploaded script for later invocation (default is examplescript.sh)")

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
	platforms := strings.Split(*platformString, ",")
	scriptFile, err := os.Open(*script)
	if err != nil {
		panic(err)
	}
	scriptReadCloser := runtime.NamedReader(*name, scriptFile)

	client, err := falcon.NewRTR(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	// First, create/upload the script for later use via the Create Script API.
	err = client.CreateScript(context.Background(), nil, "An example script to demonstrate script management via the RTR Admin APIs.",
		*permType, platforms, falcon_util.StrPtr("created example script with gofalcon SDK"), nil, scriptReadCloser)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}

	// Then invoke the script by sending the `runscript` command to the RTR Execute Admin Command API.
	session, err := client.NewSession(context.Background(), *aid)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	result, err := session.AdminExecuteAndWait(
		context.Background(), "runscript", fmt.Sprintf("runscript -CloudFile='%s'", *name))
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}

	json, _ := falcon_util.PrettyJson(result)
	fmt.Println(json)
}
