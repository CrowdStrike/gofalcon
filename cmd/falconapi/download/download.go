package download

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/crowdstrike/gofalcon/cmd/falconapi/common"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/spf13/cobra"
)

type downloadOptions struct {
	All           bool
	OS            string
	OSVersion     string
	SensorVersion string
}

var (
	opts downloadOptions

	// Command: falconapi _download_
	downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "Generate Dockerfiles from templates",
		Long:  "Generate Dockerfiles from templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			return download(cmd, args, opts)
		},
	}
)

func init() {
	common.Commands = common.AllCommands(common.CliCommand{
		Command: downloadCmd,
	})

	downloadFlags(downloadCmd)
}

func downloadFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&opts.OS, "os-name", "", "Name of the operating system")
	flags.StringVar(&opts.OSVersion, "os-version", "", "Version of the operating system")
	flags.StringVar(&opts.SensorVersion, "sensor-version", "latest", "Version of the Falcon Sensor. Use: 'latest' to get the latest or '' to get prompted interactively")
	flags.BoolVar(&opts.All, "all", false, "Download all sensors")
}

func download(cmd *cobra.Command, args []string, opts downloadOptions) error {
	client := common.APIClient

	if opts.All {
		downloadAllSensors(client)
	} else {
		if opts.OS == "" {
			validOsNames := getValidOsNames(client)
			fmt.Printf("Missing --os-name command-line option. Available OS names are: [%s]\n", strings.Join(validOsNames, ", "))
			opts.OS = falcon_util.PromptUser("Selected OS Name")
		}

		if opts.OSVersion == "" {
			validOsVersions := getValidOsVersions(client, opts.OS)
			if len(validOsVersions) == 0 {
				fmt.Fprintf(os.Stderr, "No sensors available for os: %s\n", opts.OS)
				os.Exit(1)
			}
			if len(validOsVersions) == 1 && validOsVersions[0] == "" {
				// No version distinction, single package suits all
				opts.OSVersion = ""
			} else {
				fmt.Printf("Missing --os-version command-line option. Available OS versions are: [%s]\n", strings.Join(validOsVersions, ", "))
				opts.OSVersion = falcon_util.PromptUser("Selected OS Version")
			}
		}
		if opts.SensorVersion == "" {
			validSensorVersions := getValidSensorVersions(client, opts.OS, opts.OSVersion)
			if len(validSensorVersions) == 0 {
				fmt.Fprintf(os.Stderr, "No sensors available for specified os/version tuple: %s/%s\n", opts.OS, opts.OSVersion)
				os.Exit(1)
			}
			fmt.Printf("Missing --sensor-version=latest command-line option. Available sensor versions are: [%s]\n", strings.Join(validSensorVersions, ", "))
			opts.SensorVersion = falcon_util.PromptUser("Selected Sensor Version")
		}

		sensor := querySuitableSensor(client, opts.OS, opts.OSVersion, opts.SensorVersion)
		if sensor == nil {
			fmt.Fprintf(os.Stderr, "Could not find sensor version '%s' for '%s' '%s'\n", opts.SensorVersion, opts.OS, opts.OSVersion)
			os.Exit(1)
		}

		sensorDownload(client, sensor, *sensor.Name)
	}
	return nil
}

func sensorDownload(client *client.CrowdStrikeAPISpecification, sensor *models.DomainSensorInstallerV1, filename string) {
	safeLocation := filepath.Clean(filename)
	if strings.Contains(safeLocation, "/") || strings.Contains(safeLocation, "\\") || strings.Contains(safeLocation, "..") {
		panic("Suspicious file location: " + safeLocation)
	}
	file, err := os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %s\n", err)
		}
	}()

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

func querySuitableSensor(client *client.CrowdStrikeAPISpecification, osName, osVersion, sensorVersion string) *models.DomainSensorInstallerV1 {
	for _, sensor := range getSensors(client, osName) {
		if osVersion == *sensor.OsVersion {
			if *sensor.Version == sensorVersion || sensorVersion == "latest" {
				return sensor
			}
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

func getValidSensorVersions(client *client.CrowdStrikeAPISpecification, osName, osVersion string) []string {
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
		dir := filepath.Join(strings.ReplaceAll(*sensor.Os, "/", "-"), strings.ReplaceAll(*sensor.OsVersion, "/", "-"))
		if dir != "" {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				panic(fmt.Sprintf("Could not create directory %s: %v", dir, err))
			}
		}
		filename := filepath.Join(dir, *sensor.Name)
		sensorDownload(client, sensor, filename)
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

type void struct{}
