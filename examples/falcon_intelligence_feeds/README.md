# Falcon Intelligence Feeds

This example queries the Intelligence Feeds API with a time-based cursor,
deduplicates the returned feed item IDs, and downloads the archives with a
configurable concurrency limit.

The API client needs the Falcon Indicator Graph read scope. Export the OAuth2
credentials rather than placing the client secret on the command line:

```shell
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_CLOUD="us-1"
```

Run the example with a feed name available to the customer:

```shell
go run . \
  --feed-name="your-feed-name" \
  --lookback=24h \
  --concurrency=4 \
  --output-dir=feeds
```

The query advances the `since` value to the newest `created_timestamp` in each
response until the API returns no new feed item IDs. Each download requests the
authenticated feed download endpoint, which redirects to a short-lived signed
URL. The client follows that redirect without the Falcon bearer token and
writes the gzip-compressed NDJSON archive to the output directory as
`<feed-item-id>.ndjson.gz` with mode `0600`.

Use `go run . --help` to review the available intervals and flags. Set
`FALCON_MEMBER_CID` when the OAuth2 client can access more than one CID.
