package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func main() {
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	osName := flag.String("os-name", "", "Name of the operating system")
	osVersion := flag.String("os-version", "", "Versin of the operating system")

	flag.Parse()

	if *clientId == "" {
		*clientId = promptUser("Please provide your Falcon Client ID")
	}
	if *clientSecret == "" {
		*clientSecret = promptUser("Please provide your Falcon Client Secret")
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	if *osName == "" {
		validOsNames := getValidOsNames(client)
		fmt.Printf("Missing --os-name command-line option. Valid names are: [%s]\n", strings.Join(validOsNames, ","))
		*osName = promptUser("Selected OS Name")
	}

	if *osVersion == "" {
		validOsVersions := getValidOsVersions(client, *osName)
		if len(validOsVersions) == 0 {
			fmt.Fprintf(os.Stderr, "No sensors available for os: %s\n", *osName)
			os.Exit(1)
		}
		if len(validOsVersions) == 1 && validOsVersions[0] == "" {
			// No version distinction, single package suits all
			*osVersion = ""
		} else {
			fmt.Printf("Missing --os-version command-line option. Valid version are: %s\n", validOsVersions)
			*osVersion = promptUser("Selected OS Version")
		}
	}
	sensor := querySuitableSensor(client, *osName, *osVersion)
	if sensor == nil {
		fmt.Fprintf(os.Stderr, "Could not find relevant sensor for '%s' version '%s'\n", *osName, *osVersion)
		os.Exit(1)
	}

	fmt.Printf("Downloading %s to %s\n", *sensor.Description, *sensor.Name)

	download(client, sensor)
}

func download(client *client.CrowdStrikeAPISpecification, sensor *models.DomainSensorInstallerV1) {
	file, err := os.OpenFile(*sensor.Name, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	_, err = client.SensorDownload.DownloadSensorInstallerByID(
		&sensor_download.DownloadSensorInstallerByIDParams{
			Context: context.Background(),
			ID:      *sensor.Sha256,
		}, file)
	if err != nil {
		falcon.ErrorExplain(err)
	}
	fmt.Println("OK")

}

func querySuitableSensor(client *client.CrowdStrikeAPISpecification, osName, osVersion string) *models.DomainSensorInstallerV1 {
	for _, sensor := range getSensors(client, osName) {
		if osVersion == *sensor.OsVersion {
			return sensor
		}
	}
	return nil
}

func getSensors(client *client.CrowdStrikeAPISpecification, osName string) []*models.DomainSensorInstallerV1 {
	var filter *string
	if osName != "" {
		f := fmt.Sprintf("os:\"%s\"", osName)
		filter = &f
	}
	res, err := client.SensorDownload.GetCombinedSensorInstallersByQuery(
		&sensor_download.GetCombinedSensorInstallersByQueryParams{
			Context: context.Background(),
			Filter:  filter,
		},
	)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	payload := res.GetPayload()
	if len(payload.Errors) != 0 {
		fmt.Println(payload.Errors)
		panic("Errors from the server")

	}
	return payload.Resources
}

func getValidOsNames(client *client.CrowdStrikeAPISpecification) []string {
	sensors := getSensors(client, "")
	type void struct{}
	osNames := make(map[string]void)
	for _, sensor := range sensors {
		osNames[*sensor.Os] = void{}
	}
	list := []string{}
	for k := range osNames {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

func getValidOsVersions(client *client.CrowdStrikeAPISpecification, osName string) []string {
	sensors := getSensors(client, osName)
	type void struct{}
	osVersions := make(map[string]void)
	for _, sensor := range sensors {
		osVersions[*sensor.OsVersion] = void{}
	}
	list := []string{}
	for k := range osVersions {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
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
