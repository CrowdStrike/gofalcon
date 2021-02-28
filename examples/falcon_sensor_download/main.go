package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	osName := flag.String("os-name", "", "Name of the operating system")
	osVersion := flag.String("os-version", "", "Versin of the operating system")
	all := flag.Bool("all", false, "Download all sensors")

	flag.Parse()

	if *clientId == "" {
		*clientId = promptUser(`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`)
	}
	if *clientSecret == "" {
		*clientSecret = promptUser(`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	if *all == true {
		downloadAllSensors(client)
	} else {
		if *osName == "" {
			validOsNames := getValidOsNames(client)
			fmt.Printf("Missing --os-name command-line option. Available OS names are: [%s]\n", strings.Join(validOsNames, ", "))
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
				fmt.Printf("Missing --os-version command-line option. Available version are: [%s]\n", strings.Join(validOsVersions, ", "))
				*osVersion = promptUser("Selected OS Version")
			}
		}
		sensor := querySuitableSensor(client, *osName, *osVersion)
		if sensor == nil {
			fmt.Fprintf(os.Stderr, "Could not find relevant sensor for '%s' version '%s'\n", *osName, *osVersion)
			os.Exit(1)
		}

		download(client, sensor, *sensor.Name)
	}
}

func download(client *client.CrowdStrikeAPISpecification, sensor *models.DomainSensorInstallerV1, filename string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	_, err = client.SensorDownload.DownloadSensorInstallerByID(
		&sensor_download.DownloadSensorInstallerByIDParams{
			Context: context.Background(),
			ID:      *sensor.Sha256,
		}, file)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	fmt.Printf("Downloaded %s to %s\n", *sensor.Description, filename)
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

func downloadAllSensors(client *client.CrowdStrikeAPISpecification) {
	for sensor := range oneSensorPerOsVersion(client) {
		dir := filepath.Join(strings.ReplaceAll(*sensor.Os, "/", "-"), *sensor.OsVersion)
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			panic(fmt.Sprintf("Could not create directory %s: %v", dir, err))
		}
		filename := filepath.Join(dir, *sensor.Name)
		download(client, sensor, filename)
	}
}

func oneSensorPerOsVersion(client *client.CrowdStrikeAPISpecification) <-chan *models.DomainSensorInstallerV1 {
	out := make(chan *models.DomainSensorInstallerV1)

	sensors, err := client.SensorDownload.GetCombinedSensorInstallersByQuery(
		&sensor_download.GetCombinedSensorInstallersByQueryParams{
			Context: context.Background(),
		},
	)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	go func() {
		uniq := map[string]map[string]void{}
		for _, s := range sensors.GetPayload().Resources {
			if s.Os == nil || s.OsVersion == nil {
				fmt.Fprintf(os.Stderr, "Unexpected nil field for %#v", s)
				continue
			}
			if _, ok := uniq[*s.Os]; !ok {
				uniq[*s.Os] = map[string]void{}
			}
			versions := uniq[*s.Os]

			if _, ok := versions[*s.OsVersion]; !ok {
				versions[*s.OsVersion] = void{}
				out <- s
			}
		}
		close(out)
	}()
	return out
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

type void struct{}
