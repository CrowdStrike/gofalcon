package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/go-openapi/runtime"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1; default taken from FALCON_CLOUD)")
	aid := flag.String("aid", os.Getenv("FALCON_AGENT_ID"), "Falcon agent ID of the host to put the file on (default taken from FALCON_AGENT_ID)")
	file := flag.String("file", "", "Path to the local file to upload and put on the host")
	name := flag.String("name", "", "Name to give the file in the cloud and on the host (default is the base name of -file)")
	targetDir := flag.String("target-dir", "", `Directory on the host to put the file in (for example C:\Windows\Temp or /tmp)`)
	timeout := flag.Duration("timeout", 5*time.Minute, "Maximum time allowed for the upload and all RTR commands")

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
	if *file == "" {
		*file = falcon_util.PromptUser(`Missing -file. Please provide the path to the local file to put on the host.
Local file path`)
	}
	if *targetDir == "" {
		*targetDir = falcon_util.PromptUser(`Missing -target-dir. Please provide the directory on the host to put the file in.
Target directory`)
	}
	if *name == "" {
		*name = filepath.Base(*file)
	}
	if strings.ContainsFunc(*name, unicode.IsSpace) {
		panic(fmt.Errorf("file name %q contains whitespace, which this example does not support; use -name to choose another name", *name))
	}

	localFile, err := os.Open(*file)
	if err != nil {
		panic(err)
	}
	defer localFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := falcon.NewRTR(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      ctx,
	})
	if err != nil {
		panic(err)
	}

	// Upload the file to the cloud so the RTR put command can refer to it by name.
	err = client.CreatePutFile(ctx, name, "Uploaded by the gofalcon falcon_rtr_admin_put_file example.",
		falcon_util.StrPtr("uploaded put file with gofalcon SDK"), runtime.NamedReader(*name, localFile))
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}

	session, err := client.NewSession(ctx, *aid)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	defer func() {
		if err := session.Close(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "close RTR session:", falcon.ErrorExplain(err))
		}
	}()

	// put writes into the session's working directory, so cd and put must run
	// in the same session. A cd only applies to later commands once its status
	// has been retrieved, which AdminExecuteAndWait does. On Windows hosts,
	// running pwd resets that directory to C:\, so don't run it between cd and
	// put. Quoting keeps paths with spaces, such as C:\Program Files, as a
	// single argument.
	quotedDir := fmt.Sprintf(`"%s"`, *targetDir)
	runCommand(ctx, session, "cd "+quotedDir)
	runCommand(ctx, session, "put "+*name)
	listing := runCommand(ctx, session, "ls "+quotedDir)

	fmt.Printf("Put %s into %s\n\n%s\n", *name, *targetDir, listing)
}

// runCommand runs an RTR admin command in the session and returns its output.
// RTR reports command failures, such as a file that already exists, on stderr
// rather than as an API error, so non-empty stderr is treated as a failure.
func runCommand(ctx context.Context, session *falcon.RTRSession, commandString string) string {
	baseCommand, _, _ := strings.Cut(commandString, " ")
	result, err := session.AdminExecuteAndWait(ctx, baseCommand, commandString)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	if stderr := falcon_util.DerefString(result.Stderr); stderr != "" {
		panic(fmt.Errorf("%s: %s", commandString, stderr))
	}
	return falcon_util.DerefString(result.Stdout)
}
