This is a working standalone example of a program that uploads a local file
using the RTR Create Put File API and then places it in a chosen directory on
an agent via the RTR Execute Admin Command API.

The RTR `put` command writes the file into the session's current working
directory, so the example runs `cd` to the target directory and then `put` in
the same RTR session. It then lists the target directory to show the file
arrived.

Note that the API client key used for this example will need to be granted
the RTR Administrator permission for this program to run successfully.

For more information on managing RTR put files as an Administrator, see the
[Real Time Response APIs](https://developer.crowdstrike.com/crowdstrike/docs/real-time-response-apis)
section of the Falcon developer API documentation.

## Build
```
go install github.com/crowdstrike/gofalcon/examples/falcon_rtr_admin_put_file@latest
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
      falcon_rtr_admin_put_file --aid="def" \
      --file="relative path to the local file from current working directory" \
      --target-dir='C:\Windows\Temp'
```

Optional flags: `--name` sets the file name in the cloud and on the host
(default is the base name of `--file`, and it must not contain whitespace),
and `--timeout` limits how long the upload and RTR commands may take (default
`5m`).

## Notes

### Working directory

* `cd` sets the working directory for later commands in the same RTR
  session, so `cd` and `put` must be sent through the same session.
* A `cd` only applies to later commands once its status has been retrieved.
  `AdminExecuteAndWait` does this. If `cd` is sent with `AdminExecute` and its
  status is never retrieved, later commands, including `put`, still run from
  the previous directory.
* On Windows hosts, retrieving the result of `pwd` has been observed to reset
  the session's working directory to `C:\`. Avoid running `pwd` between `cd`
  and `put`, or run `cd` again after it.

### Existing files

* `put` fails if a file with the same name already exists in the target
  directory. Use `--name` to give the file a different name.
* The uploaded put file stays in the cloud after the example finishes, and
  uploading another put file with the same name fails with HTTP 409 Conflict.
  Remove the old one with the `DeletePutFile` method of `falcon.RTR`, or use
  `--name` to choose a different name.
