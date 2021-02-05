# Falcon Sensor Download

Minimalist example to show download of CrowdStrike Falcon Sensor through API. This example can be run interactively or in script when all information is passed in through command-line.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_sensor_download
```

## Example Run

Download single sensor package interactively
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" falcon_sensor_download
Missing --os-name command-line option. Available OS names are: [Amazon Linux, Container, Debian, RHEL/CentOS/Oracle, SLES, Windows, macOS]
Selected OS Name: SLES
Missing --os-version command-line option. Available version are: [11, 12, 15]
Selected OS Version: 15
Downloaded Falcon Kernel Sensor for SLES 15 to falcon-sensor-6.14.0-11110.suse15.x86_64.rpm

$ ls falcon-sensor-6.14.0-11110.suse15.x86_64.rpm
falcon-sensor-6.14.0-11110.suse15.x86_64.rpm
```

Download the latest build of sensor, one package per OS Version
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" falcon_sensor_download --all
```

Download Falcon Container Sensor
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" falcon_sensor_download --os-name=Container
Downloaded Falcon Usermode Container Sensor to falcon-sensor-6.18.0-106.container.x86_64.tar.bz2
```
