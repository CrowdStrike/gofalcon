# Falcon Supported Kernels

Minimalist example to show case listing of the supported Linux kernels. The tool outputs short list of recently supported kernels by CrowdStrike Falcon Sensor for Linux on a given distribution.

## Installation

```
go get github.com/crowdstrike/gofalcon/examples/falcon_supported_kernels
```

## Example Run

Print short list of recent supported kernel versions interactively:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" \
     falcon_supported_kernels
Missing --distro command-line option. Available distributions are: [amzn1, amzn2, debian10, debian9, elrepo7, oracle6, oracle7, oracle8, rhel6, rhel7, rhel8, suse11, suse12, suse15, ubuntu16, ubuntu18, ubuntu20]
Selected distro: amzn2
Missing --arch command-line option. Available architectures are: [aarch64, x86_64]
Selected architecture: aarch64
[
    "4.14.173-137.228.amzn2.aarch64",
    ......
]
```

Print short list of recent supported kernel versions non-interactively:
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" \
     falcon_supported_kernels --distro=ubuntu20
[
    "5.4.0-1049-aws",
    "5.4.0-1016-azure",
    "5.4.0-1068-gcp",
    ....
]
```
