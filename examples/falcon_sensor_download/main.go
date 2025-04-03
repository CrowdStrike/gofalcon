package main

import (
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
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	clientId := flag.String(
		"client-id",
		os.Getenv("FALCON_CLIENT_ID"),
		"Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)",
	)
	clientSecret := flag.String(
		"client-secret",
		os.Getenv("FALCON_CLIENT_SECRET"),
		"Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)",
	)
	memberCID := flag.String(
		"member-cid",
		os.Getenv("FALCON_MEMBER_CID"),
		"Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)",
	)
	clientCloud := flag.String(
		"cloud",
		os.Getenv("FALCON_CLOUD"),
		"Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)",
	)
	osName := flag.String("os-name", "", "Name of the operating system")
	osVersion := flag.String("os-version", "", "Versin of the operating system")
	sensorVersion := flag.String(
		"sensor-version",
		"latest",
		"Version of the Falcon Sensor. Use: 'latest' to get the latest or '' to get prompted interactively",
	)

	all := flag.Bool("all", false, "Download all sensors")

	flag.Parse()

	if *clientId == "" {
		*clientId = falcon_util.PromptUser(
			`Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client ID`,
		)
	}
	if *clientSecret == "" {
		*clientSecret = falcon_util.PromptUser(
			`Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.
Falcon Client Secret`,
		)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		MemberCID:    *memberCID,
		Cloud:        falcon.Cloud(*clientCloud),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	if *all {
		downloadAllSensors(client)
	} else {
		if *osName == "" {
			validOsNames := getValidOsNames(client)
			fmt.Printf("Missing --os-name command-line option. Available OS names are: [%s]\n", strings.Join(validOsNames, ", "))
			*osName = falcon_util.PromptUser("Selected OS Name")
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
				fmt.Printf("Missing --os-version command-line option. Available OS versions are: [%s]\n", strings.Join(validOsVersions, ", "))
				*osVersion = falcon_util.PromptUser("Selected OS Version")
			}
		}
		if *sensorVersion == "" {
			validSensorVersions := getValidSensorVersions(client, *osName, *osVersion)
			if len(validSensorVersions) == 0 {
				fmt.Fprintf(os.Stderr, "No sensors available for specified os/version tuple: %s/%s\n", *osName, *osVersion)
				os.Exit(1)
			}
			fmt.Printf("Missing --sensor-version=latest command-line option. Available sensor versions are: [%s]\n", strings.Join(validSensorVersions, ", "))
			*sensorVersion = falcon_util.PromptUser("Selected Sensor Version")
		}

		sensor := querySuitableSensor(client, *osName, *osVersion, *sensorVersion)
		if sensor == nil {
			fmt.Fprintf(os.Stderr, "Could not find sensor version '%s' for '%s' '%s'\n", *sensorVersion, *osName, *osVersion)
			os.Exit(1)
		}

		download(client, sensor, ".", *sensor.Name)
	}
}

func download(
	client *client.CrowdStrikeAPISpecification,
	sensor *models.DomainSensorInstallerV1,
	dir, filename string,
) {
	file, err := openFileForWriting(dir, filename)
	if err != nil {
		panic(err)
	}

	_, err = client.SensorDownload.DownloadSensorInstallerByID(
		&sensor_download.DownloadSensorInstallerByIDParams{
			Context: context.Background(),
			ID:      *sensor.Sha256,
		}, file)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}

	if err := file.Close(); err != nil {
		panic(err)
	}

	fmt.Printf("Downloaded %s to %s\n", *sensor.Description, filename)
}

func querySuitableSensor(
	client *client.CrowdStrikeAPISpecification,
	osName, osVersion, sensorVersion string,
) *models.DomainSensorInstallerV1 {
	for _, sensor := range getSensors(client, osName) {
		if osVersion == *sensor.OsVersion {
			if *sensor.Version == sensorVersion || sensorVersion == "latest" {
				return sensor
			}
		}
	}
	return nil
}

func getSensors(
	client *client.CrowdStrikeAPISpecification,
	osName string,
) []*models.DomainSensorInstallerV1 {
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
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		panic(err)
	}

	k := 0
	for _, sensor := range payload.Resources {
		if strings.Contains(*sensor.Description, "Falcon SIEM Connector") {
			continue
		}
		payload.Resources[k] = sensor
		k++
	}
	return payload.Resources[:k]
}

func getValidOsNames(client *client.CrowdStrikeAPISpecification) []string {
	sensors := getSensors(client, "")
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

func getValidSensorVersions(
	client *client.CrowdStrikeAPISpecification,
	osName, osVersion string,
) []string {
	sensors := getSensors(client, osName)
	sensorVersions := make(map[string]void)
	for _, sensor := range sensors {
		if *sensor.OsVersion == osVersion {
			sensorVersions[*sensor.Version] = void{}
		}
	}
	list := []string{}
	for k := range sensorVersions {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

func downloadAllSensors(client *client.CrowdStrikeAPISpecification) {
	for sensor := range oneSensorPerOsVersion(client) {
		dir := filepath.Join(
			strings.ReplaceAll(*sensor.Os, "/", "-"),
			strings.ReplaceAll(*sensor.OsVersion, "/", "-"),
		)
		if dir != "" {
			err := os.MkdirAll(dir, 0750)
			if err != nil {
				panic(fmt.Sprintf("Could not create directory %s: %v", dir, err))
			}
		}
		download(client, sensor, dir, *sensor.Name)
	}
}

func oneSensorPerOsVersion(
	client *client.CrowdStrikeAPISpecification,
) <-chan *models.DomainSensorInstallerV1 {
	out := make(chan *models.DomainSensorInstallerV1)

	sensors, err := client.SensorDownload.GetCombinedSensorInstallersByQuery(
		&sensor_download.GetCombinedSensorInstallersByQueryParams{
			Context: context.Background(),
		},
	)
	if err != nil {
		panic(falcon.ErrorExplain(err))
	}
	if err = falcon.AssertNoError(sensors.Payload.Errors); err != nil {
		panic(err)
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

func openFileForWriting(dir, filename string) (*os.File, error) {
	if strings.Contains(filename, "/") {
		return nil, fmt.Errorf("refusing to download: '%s' includes '/' character", filename)
	}
	path := filepath.Join(dir, filename)
	safeLocation := filepath.Clean(path)
	if strings.Contains(safeLocation, "\\") || strings.Contains(safeLocation, "..") {
		return nil, fmt.Errorf("refusing to download: Path '%s' looks suspicious", safeLocation)
	}
	return os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY, 0600)
}

type void struct{}
