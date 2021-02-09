package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	flag.Parse()

	if *clientId == "" {
		*clientId = promptUser("Please provide your Falcon Client ID")
	}
	if *clientSecret == "" {
		*clientSecret = promptUser("Please provide your Falcon Client Secret")
	}

	config := clientcredentials.Config{
		ClientID:     *clientId,
		ClientSecret: *clientSecret,
		TokenURL:     "https://" + client.DefaultHost + "/oauth2/token",
	}
	token, err := config.Token(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(token.AccessToken)
}

func promptUser(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	s, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(s)
}
