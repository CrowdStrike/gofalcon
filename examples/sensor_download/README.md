# Sensor Download

Minimalist example to show download of CrowdStrike Falcon sensor through API. This example can be run interactively or in script when all information is passed in through command-line.

Example run:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" \
        go run github.com/crowdstrike/gofalcon/examples/sensor_download
Missing --os-name command-line option. Available OS names are: [Amazon Linux, Debian, RHEL/CentOS/Oracle, SLES, Windows, macOS]
Selected OS Name: SLES
Missing --os-version command-line option. Available version are: [11, 12, 15]
Selected OS Version: 15
Downloaded Falcon Kernel Sensor for SLES 15 to falcon-sensor-6.14.0-11110.suse15.x86_64.rpm

$ ls falcon-sensor-6.14.0-11110.suse15.x86_64.rpm
falcon-sensor-6.14.0-11110.suse15.x86_64.rpm
```
