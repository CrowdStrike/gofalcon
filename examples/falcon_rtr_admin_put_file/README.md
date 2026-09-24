This is a working standalone example of a program that uploads a local file
using the RTR Create Put File API and then places it in a chosen directory on
an agent via the RTR Execute Admin Command API.

The RTR `put` command writes the file into the session's current working
directory, so the example runs `cd` to the target directory and then `put` in
the same RTR session. It fails if either command reports an error. The
uploaded put file stays in the cloud after a successful run; if a step after
the upload fails, the example deletes it again. The exception is when `put`
was sent but its result couldn't be retrieved, for example because
`--timeout` expired: the file may already be on the host, so the put file is
kept.

Note that the API client key used for this example will need to be granted
the RTR Administrator permission for this program to run successfully, and
the Hosts read permission to use `--hostname`.

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
export FALCON_AGENT_ID="agent ID of the host to put the file on (leave unset to use --hostname)"
```

## Usage
```
$ FALCON_CLIENT_ID="abc" FALCON_CLIENT_SECRET="XYZ" FALCON_CLOUD=us-1 \
      falcon_rtr_admin_put_file --aid="def" \
      --file="relative path to the local file from current working directory" \
      --target-dir='C:\Windows\Temp'
```

Instead of `--aid`, `--hostname` looks up the agent ID by host name. The name
must match exactly, including case. It fails if no host or more than one host
has that name; use `--aid` to choose one. `--hostname` can't be combined with
`--aid` or `FALCON_AGENT_ID`.

Optional flags:

* `--name` sets the file name in the cloud and on the host. The default is the
  base name of `--file`. RTR does not accept names that contain `'` or `"`,
  and the example also rejects `/` and `\`.
* `--timeout` is the deadline for opening the RTR session, the upload and the
  RTR commands (default `5m`). It also replaces the SDK's default 5 minute
  HTTP timeout, so raise it to upload large files. Closing the session, and
  deleting the put file after a failure, can each take up to 30 seconds more.

## Notes

### Working directory

* `cd` sets the working directory for later commands in the same RTR
  session, so `cd` and `put` must be sent through the same session.
* RTR gives every run that uses the same API client on the same host the same
  session. Don't run the example on a host while another run is using it:
  one run's `cd` can change where the other's `put` writes, and the first run
  to finish closes the session for both.
* A `cd` only applies to later commands once its status has been retrieved.
  `AdminExecuteAndWait` does this. If `cd` is sent with `AdminExecute` and its
  status is never retrieved, later commands, including `put`, still run from
  the previous directory.
* Be careful using `pwd` on Windows hosts: retrieving its result has been
  seen to reset the working directory to `C:\`.

### Existing files

* `put` fails if a file with the same name already exists in the target
  directory. Use `--name` to give the file a different name.
* The uploaded put file stays in the cloud after a successful run, so
  uploading another put file with the same name fails with HTTP 409 Conflict.
  Use `--name` to choose a different name, or delete the old put file:
  `DeletePutFile` takes its ID, which `ListPutFiles` returns for the filter
  `name:'<name>'`. If a step after the upload fails, the example deletes the
  put file itself, unless `put`'s result couldn't be retrieved.
