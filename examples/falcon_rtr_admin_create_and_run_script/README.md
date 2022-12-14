This is a working standalone example of a program to upload a stored script
using the RTR Create Script API and then running it against an agent
via the RTR Execute Admin Command API.

Note that the API client key used for this example will need to be granted
the RTR Administrator permission for this script to run successfully.

For more information on managing RTR scripts as an Administrator, see the
[Manage Real Time Response scripts](https://developer.crowdstrike.com/crowdstrike/docs/real-time-response-apis#manage-real-time-response-scripts)
section of the Falcon developer API documentation.

## Build
```
go get github.com/crowdstrike/gofalcon/examples/falcon_rtr_upload_and_run_script
```

## Setup Environment Variables
```
export FALCON_CLIENT_ID="your_falcon_id"
export FALCON_CLIENT_SECRET="your_falcon_secret"
export FALCON_CLOUD="us-1, us-2, eu-1, us-gov-1, etc"
```

## Usage
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_rtr_admin_create_and_run_script --permtype group --platforms="linux,mac" \
      --script="relative path to script file from current working directory" \
      --name="name of the file to use when invoking runscript with the `-CloudFile` option" \
      --aid="def"
```

## Notes

### Script types by platform

* Scripts targeting Windows will be interpreted with PowerShell
* Scripts targeting Linux will be interpreted with bash
* Scripts targeting macOS will be interpreted with Zsh

### Permission Type

Valid values for the `permtype` argument are:

* private: script can only be invoked by the user who uploaded it
* group: script can only be invoked by RTR Administrators
* public: script can be invoked by RTR Administrators and RTR Active Responders

Default value for `permtype` is `group`.

### Platforms

The `platforms` argument is a comma-delimited string of one or more of either
"windows", "linux", or "mac".

If not specified, the default for this example code is "linux", though when
using the Falcon API or gofalcon SDK directly the default is "windows".
