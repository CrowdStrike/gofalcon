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

Download specified version of Falcon Sensor
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" falcon_sensor_download --os-name Ubuntu --os-version '14/16/18/20' --sensor-version=5.43.10807
Downloaded Falcon Kernel Sensor for Ubuntu 14.04LTS, 16.04LTS, 18.04LTS, and 20.04LTS to falcon-sensor_5.43.0-10807_amd64.deb
```

