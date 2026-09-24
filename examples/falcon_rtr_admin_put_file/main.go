package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/go-openapi/runtime"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1; default taken from FALCON_CLOUD)")
	aid := flag.String("aid", os.Getenv("FALCON_AGENT_ID"), "Falcon agent ID of the host to put the file on (default taken from FALCON_AGENT_ID)")
	hostname := flag.String("hostname", "", "Host name to look up the agent ID by, instead of -aid; must match exactly, including case (needs the Hosts read permission)")
	file := flag.String("file", "", "Path to the local file to upload and put on the host")
	name := flag.String("name", "", "Name to give the file in the cloud and on the host (default is the base name of -file)")
	targetDir := flag.String("target-dir", "", `Directory on the host to put the file in (for example C:\Windows\Temp or /tmp)`)
	timeout := flag.Duration("timeout", 5*time.Minute, "Maximum time allowed for the RTR session, the upload and all RTR commands; raise it for large files")

	flag.Parse()
	if *aid != "" && *hostname != "" {
		panic("-aid (or FALCON_AGENT_ID) and -hostname must not both be set")
	}
	if *clientId == "" {
		*clientId = falcon_util.PromptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}
	if *aid == "" && *hostname == "" {
		*aid = falcon_util.PromptUser(`Missing FALCON_AGENT_ID. Please provide the ID of the agent you would like to communicate with, or rerun with -hostname.
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
	if (*aid == "" && *hostname == "") || *file == "" || *targetDir == "" {
		panic("-aid or -hostname, -file and -target-dir must not be empty")
	}
	if err := checkName(*name); err != nil {
		panic(err)
	}
	if strings.Contains(*targetDir, `"`) {
		panic(fmt.Errorf("target directory %q must not contain double quotes", *targetDir))
	}
	if strings.Contains(*hostname, "'") {
		panic(fmt.Errorf("host name %q must not contain single quotes", *hostname))
	}

	// CreatePutFile closes localFile once it has been uploaded.
	localFile, err := os.Open(*file)
	if err != nil {
		panic(err)
	}
	if info, err := localFile.Stat(); err != nil {
		panic(err)
	} else if info.IsDir() {
		panic(fmt.Errorf("%s is a directory, not a file", *file))
	}

	config := &falcon.ApiConfig{
		ClientId:            *clientId,
		ClientSecret:        *clientSecret,
		Cloud:               falcon.Cloud(*clientCloud),
		Context:             context.Background(),
		HttpTimeOutOverride: timeout,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *hostname != "" {
		*aid, err = agentID(ctx, config, *hostname)
		if err != nil {
			panic(falcon.ErrorExplain(err))
		}
		fmt.Printf("Host %s has agent ID %s\n", *hostname, *aid)
	}

	client, err := falcon.NewRTR(config)
	if err != nil {
		panic(err)
	}

	// Open the session first so an offline host or a wrong agent ID fails
	// before anything is uploaded.
	session := openSession(ctx, client, *aid)
	defer func() {
		// Use a fresh context so the session is still closed after ctx expires.
		closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := session.Close(closeCtx); err != nil {
			fmt.Fprintln(os.Stderr, "close RTR session:", falcon.ErrorExplain(err))
		}
	}()

	// Upload the file to the cloud so the RTR put command can refer to it by name.
	err = client.CreatePutFile(ctx, name, "Uploaded by the gofalcon falcon_rtr_admin_put_file example.",
		falcon_util.StrPtr("uploaded put file with gofalcon SDK"), runtime.NamedReader(*name, localFile))
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) && apiErr.IsCode(http.StatusConflict) {
		panic(fmt.Errorf("a put file named %q already exists in the cloud; use -name to choose another name", *name))
	}
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	// If a later step fails, remove the put file from the cloud so the example
	// can be run again with the same name. It is kept after a successful put,
	// and when put's result couldn't be retrieved.
	keepPutFile := false
	defer func() {
		if !keepPutFile {
			deletePutFile(client, *name)
		}
	}()

	// RTR closes a session after 10 minutes without activity, which a long
	// upload can exceed, and an expired session can't be pulsed. Opening the
	// session again returns it if it is still open and starts a new one if not.
	session = openSession(ctx, client, *aid)

	// put writes into the session's working directory, so cd and put must run
	// in the same session. See the README for why each command's status must
	// be retrieved.
	if err := runCommand(ctx, session, `cd "`+*targetDir+`"`); err != nil {
		panic(err)
	}
	if err := runCommand(ctx, session, `put "`+*name+`"`); err != nil {
		if errors.Is(err, errNoResult) {
			// put may have written the file even though its result couldn't
			// be retrieved, so keep the put file and say so.
			keepPutFile = true
			panic(fmt.Errorf("%s may already be in %s, so the put file was kept: %w", *name, *targetDir, err))
		}
		panic(err)
	}
	keepPutFile = true

	fmt.Printf("Put %s into %s\n", *name, *targetDir)
}

// agentID returns the agent ID of the host named hostname. The name must match
// exactly, including case. It fails when more than one host has that name, so
// a command is never sent to the wrong one.
func agentID(ctx context.Context, config *falcon.ApiConfig, hostname string) (string, error) {
	client, err := falcon.NewClient(config)
	if err != nil {
		return "", err
	}
	// hostname:'...' matches every host whose name starts with the value,
	// ignoring case; hostname:['...'] matches only the exact name.
	filter := fmt.Sprintf("hostname:['%s']", hostname)
	response, err := client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
		Context: ctx,
		Filter:  &filter,
	})
	if err != nil {
		return "", err
	}
	switch ids := response.Payload.Resources; len(ids) {
	case 0:
		return "", fmt.Errorf("no host is named %q (the name must match exactly, including case)", hostname)
	case 1:
		return ids[0], nil
	default:
		return "", fmt.Errorf("%d hosts are named %q (%s); use -aid to choose one", len(ids), hostname, strings.Join(ids, ", "))
	}
}

// openSession opens an RTR session on the host with agent ID aid, or returns
// the session this API client already has open on it.
func openSession(ctx context.Context, client *falcon.RTR, aid string) *falcon.RTRSession {
	session, err := client.NewSession(ctx, aid)
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) && apiErr.IsCode(http.StatusNotFound) {
		panic(fmt.Errorf("no host has agent ID %q", aid))
	}
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	return session
}

// checkName rejects put file names that RTR does not accept or that would not
// name a single file in the target directory.
func checkName(name string) error {
	switch {
	case name == "." || name == "..":
		return fmt.Errorf("file name %q is not a file name; use -name to choose another", name)
	case strings.ContainsAny(name, `'"/\`):
		return fmt.Errorf("file name %q must not contain quotes or path separators", name)
	}
	return nil
}

// errNoResult means an RTR command's result couldn't be retrieved, so the
// command may or may not have run on the host.
var errNoResult = errors.New("could not get the command's result")

// runCommand runs an RTR admin command in the session. RTR reports command
// failures, such as a file that already exists, on stderr rather than as an
// API error, so non-empty stderr is treated as a failure. Any other error
// wraps errNoResult.
func runCommand(ctx context.Context, session *falcon.RTRSession, commandString string) error {
	baseCommand, _, _ := strings.Cut(commandString, " ")
	result, err := session.AdminExecuteAndWait(ctx, baseCommand, commandString)
	if err != nil {
		return fmt.Errorf("%s: %w: %s", commandString, errNoResult, falcon.ErrorExplain(err))
	}
	if stderr := falcon_util.DerefString(result.Stderr); stderr != "" {
		return fmt.Errorf("%s: %s", commandString, stderr)
	}
	return nil
}

// deletePutFile removes the put file named name from the cloud. CreatePutFile
// does not return the new put file's ID, so it is looked up by name; the name
// filter matches the exact name only.
func deletePutFile(client *falcon.RTR, name string) {
	// Use a fresh context so the put file is still deleted after ctx expires.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	filter := fmt.Sprintf("name:'%s'", name)
	list, err := client.ListPutFiles(ctx, &filter, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "find put file:", falcon.ErrorExplain(err))
		return
	}
	if len(list.Resources) != 1 {
		fmt.Fprintf(os.Stderr, "found %d put files named %q; not deleting any\n", len(list.Resources), name)
		return
	}
	if err := client.DeletePutFile(ctx, list.Resources[0]); err != nil {
		fmt.Fprintln(os.Stderr, "delete put file:", falcon.ErrorExplain(err))
	}
}
