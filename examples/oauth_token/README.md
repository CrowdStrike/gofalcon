# OAuth2 Token Retrieval

**Please use [falcon.NewClient()](https://pkg.go.dev/github.com/crowdstrike/gofalcon@main/falcon#NewClient) to get authenticated API client.**

This example shows inner working of OAuth2 Token retrieval based on *Client ID* and *Client Secret*. In most cases, users will want to use [falcon.NewClient()](https://pkg.go.dev/github.com/crowdstrike/gofalcon@main/falcon#NewClient) to receive authenticated client. This example is only useful when you need obtain OAuth2 token for use outside of gofalcon.
