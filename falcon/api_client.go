package falcon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/crowdstrike/gofalcon/falcon/client"
	httpruntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"gopkg.in/yaml.v3"
)

// NewClient return newly configured API Client based on configuration supplied by user.
// NewClient function is preferred entry-point to gofalcon SDK.
func NewClient(ac *ApiConfig) (*client.CrowdStrikeAPISpecification, error) {
	if ok, err := credentialsOk(ac); !ok {
		return nil, err
	}
	if ac.Context == nil {
		return nil, errors.New("invalid context for falcon.ApiConfig.Context. Make that ApiConfig.Context is set")
	}

	// If HostOverride is provided we do not need to discover the cloud
	if ac.HostOverride == "" {
		if ac.AccessToken == "" {
			if err := ac.Cloud.Autodiscover(ac.Context, ac.ClientId, ac.ClientSecret); err != nil {
				return nil, err
			}
		} else if ac.Cloud == CloudAutoDiscover {
			// There is nothing in the access token (JWT) which identifies the cloud.
			return nil, errors.New("cannot autodiscover cloud when using an access token. Please specify the cloud explicitly")
		}
	}

	var authenticatedClient *http.Client
	if ac.AccessToken == "" {
		authenticatedClient = clientCredentialsHTTPClient(ac)
	} else {
		authenticatedClient = accessTokenHTTPClient(ac)
	}

	customTransport := httptransport.NewWithClient(ac.Host(), ac.BasePath(), []string{}, authenticatedClient)
	customTransport.Debug = ac.Debug
	registerDownloadConsumers(customTransport)

	return client.New(customTransport, strfmt.Default), nil
}

// registerDownloadConsumers registers response consumers for the content types
// that CrowdStrike download and export endpoints advertise but the go-openapi
// runtime leaves unhandled by default. Binary payloads stream through verbatim.
// The structured JSON, CSV, and YAML types decode normally, unless the caller
// passes an io.Writer or io.ReaderFrom target, in which case the download-aware
// consumer streams the raw response bytes instead of decoding them.
func registerDownloadConsumers(t *httptransport.Runtime) {
	byteStream := httpruntime.ByteStreamConsumer()
	for _, mediaType := range binaryDownloadMediaTypes() {
		t.Consumers[mediaType] = byteStream
	}

	jsonConsumer := downloadAwareConsumer(httpruntime.JSONConsumer())
	yamlConsumer := downloadAwareConsumer(yamlJSONConsumer())
	t.Consumers["application/json"] = jsonConsumer
	t.Consumers["application/schema+json"] = jsonConsumer
	t.Consumers["application/x-ndjson"] = jsonConsumer
	t.Consumers["text/csv"] = downloadAwareConsumer(httpruntime.CSVConsumer())
	t.Consumers["application/yaml"] = yamlConsumer
	t.Consumers["application/x-yaml"] = yamlConsumer
}

// yamlJSONConsumer decodes YAML response bodies by converting them to JSON and
// unmarshaling with encoding/json. Generated models carry only json struct tags,
// so decoding YAML directly maps fields by lowercased Go field name and silently
// drops any whose wire name differs (for example created_timestamp or trace_id).
// Routing through JSON makes those json tags authoritative and keeps decoding
// consistent with the JSON consumer.
func yamlJSONConsumer() httpruntime.Consumer {
	return httpruntime.ConsumerFunc(func(reader io.Reader, data any) error {
		var intermediate any
		if err := yaml.NewDecoder(reader).Decode(&intermediate); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode yaml: %w", err)
		}

		encoded, err := json.Marshal(intermediate)
		if err != nil {
			return fmt.Errorf("convert yaml to json: %w", err)
		}

		if err := json.Unmarshal(encoded, data); err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
		return nil
	})
}

// downloadAwareConsumer streams download payloads (io.Writer / io.ReaderFrom targets)
// verbatim through the byte-stream consumer, preserving the exact response bytes, and
// decodes every other response with fallback.
func downloadAwareConsumer(fallback httpruntime.Consumer) httpruntime.Consumer {
	byteStream := httpruntime.ByteStreamConsumer()
	return httpruntime.ConsumerFunc(func(reader io.Reader, data any) error {
		switch data.(type) {
		case io.Writer, io.ReaderFrom:
			return byteStream.Consume(reader, data)
		default:
			return fallback.Consume(reader, data)
		}
	})
}

// binaryDownloadMediaTypes lists the binary content types returned by download
// and streaming endpoints, such as message-center case-attachment downloads and
// the workflow event stream, that the go-openapi runtime does not register a
// consumer for by default. Each is streamed verbatim into the response payload
// rather than decoded. The structured JSON, CSV, and YAML content types those
// endpoints also advertise are registered separately and are intentionally absent.
// binary/octet-stream is not advertised by any endpoint: it is S3's default
// content type, served by the presigned URL that feed downloads redirect to.
func binaryDownloadMediaTypes() []string {
	return []string{
		"application/gzip",
		"application/msword",
		"application/pdf",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/x-7z-compressed",
		"application/zip",
		"binary/octet-stream",
		"image/bmp",
		"image/gif",
		"image/jpeg",
		"image/jpg",
		"image/png",
		"text/event-stream",
	}
}

func credentialsOk(ac *ApiConfig) (bool, error) {
	hasAccessToken := ac.AccessToken != ""
	hasClientIDSecret := ac.ClientId != "" && ac.ClientSecret != ""

	if (hasAccessToken && hasClientIDSecret) || (!hasAccessToken && !hasClientIDSecret) {
		return false, errors.New("must provide either an access token or a client ID and secret, but not both and not neither")
	}
	return true, nil
}

func accessTokenHTTPClient(ac *ApiConfig) *http.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: ac.AccessToken})
	return commonHTTPClientConfig(oauth2HTTPClient(ac, ts), ac)
}

func clientCredentialsHTTPClient(ac *ApiConfig) *http.Client {
	config := clientcredentials.Config{
		ClientID:     ac.ClientId,
		ClientSecret: ac.ClientSecret,
		TokenURL:     "https://" + ac.Host() + "/oauth2/token",
	}

	if ac.MemberCID != "" {
		config.EndpointParams = url.Values{
			"member_cid": []string{ac.MemberCID},
		}
	}
	return commonHTTPClientConfig(oauth2HTTPClient(ac, config.TokenSource(tokenRequestContext(ac))), ac)
}

// oauth2HTTPClient builds the client oauth2.NewClient would, except that the
// bearer token oauth2.Transport attaches to every request is removed from
// redirect hops to hosts that may not receive credentials.
func oauth2HTTPClient(ac *ApiConfig, src oauth2.TokenSource) *http.Client {
	cc := contextHTTPClient(ac.Context)
	return &http.Client{
		Transport: &oauth2.Transport{
			Base:   &redirectAuthStripper{T: cc.Transport, host: ac.Host()},
			Source: oauth2.ReuseTokenSource(nil, src),
		},
		CheckRedirect: cc.CheckRedirect,
		Jar:           cc.Jar,
		Timeout:       cc.Timeout,
	}
}

// tokenRequestContext returns ac.Context with an oauth2.HTTPClient that refuses
// redirects to hosts that may not receive credentials. The token request
// carries the client secret, so following such a redirect would hand it over.
func tokenRequestContext(ac *ApiConfig) context.Context {
	tc := *contextHTTPClient(ac.Context)
	tc.CheckRedirect = refuseUntrustedRedirect(ac.Host(), tc.CheckRedirect)
	return context.WithValue(ac.Context, oauth2.HTTPClient, &tc)
}

// contextHTTPClient returns the http.Client oauth2 uses for ctx: the one stored
// under oauth2.HTTPClient, or http.DefaultClient.
func contextHTTPClient(ctx context.Context) *http.Client {
	if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return hc
	}
	return http.DefaultClient
}

// credentialHost reports whether credentials may be sent to u: over https, to
// apiHost or, on the default port, to a CrowdStrike cloud API host. CrowdStrike
// redirects requests made to the wrong cloud to the right one (for example
// api.us-2.crowdstrike.com to api.crowdstrike.com:443), and those hops must keep
// their credentials.
func credentialHost(u *url.URL, apiHost string) bool {
	if u.Scheme != "https" {
		return false
	}
	if u.Host == apiHost {
		return true
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	for c := CloudType(CloudUs1); c <= CloudGov2; c++ {
		if u.Hostname() == c.Host() {
			return true
		}
	}
	return false
}

// redirectAuthStripper sits beneath oauth2.Transport so it sees the
// Authorization header oauth2 sets on each hop, and drops it when a redirect
// goes to a host that may not receive credentials, such as the presigned
// storage URL a feed download redirects to. The redirect is still followed.
type redirectAuthStripper struct {
	T    http.RoundTripper
	host string
}

func (s *redirectAuthStripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response != nil && !credentialHost(req.URL, s.host) {
		req = req.Clone(req.Context())
		req.Header.Del("Authorization")
	}
	t := s.T
	if t == nil {
		t = http.DefaultTransport
	}
	return t.RoundTrip(req)
}

// refuseUntrustedRedirect returns a CheckRedirect policy that rejects redirects
// to hosts that may not receive credentials, then defers to next. A nil next
// keeps the net/http default of stopping after 10 redirects.
func refuseUntrustedRedirect(apiHost string, next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !credentialHost(req.URL, apiHost) {
			return fmt.Errorf("refusing redirect to %s://%s: credentials are only sent over https to %s or a CrowdStrike API host", req.URL.Scheme, req.URL.Host, apiHost)
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

func commonHTTPClientConfig(c *http.Client, ac *ApiConfig) *http.Client {
	c.Timeout = ac.HttpTimeout()
	rt := &roundTripper{
		T:         &workaround{T: c.Transport},
		UserAgent: ac.UserAgent(),
	}
	rt.remaining.Store(-1)
	c.Transport = rt

	if ac.RetryConfig != nil {
		c.Transport = &retryTransport{T: c.Transport, config: ac.RetryConfig}
	}

	if ac.TransportDecorator != nil {
		c.Transport = ac.TransportDecorator(c.Transport)
	}

	return c
}

const (
	rateLimitThresholdHigh int64 = 10
	rateLimitThresholdLow  int64 = 5
)

type roundTripper struct {
	T         http.RoundTripper
	UserAgent string
	remaining atomic.Int64
}

func (rt *roundTripper) proactiveDelay() time.Duration {
	remaining := rt.remaining.Load()
	switch {
	case remaining < 0:
		return 0
	case remaining <= rateLimitThresholdLow:
		return 500 * time.Millisecond
	case remaining <= rateLimitThresholdHigh:
		return 200 * time.Millisecond
	default:
		return 0
	}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", rt.UserAgent)
	req.Header.Add("CrowdStrike-SDK", "crowdstrike-gofalcon/"+Version.String())

	if delay := rt.proactiveDelay(); delay > 0 {
		log.Debugf("Approaching CrowdStrike API rate limits (remaining=%d). Waiting %s.",
			rt.remaining.Load(), delay)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		}
	}

	response, err := rt.T.RoundTrip(req)
	if response != nil {
		if s := response.Header.Get("X-Ratelimit-Remaining"); s != "" {
			if v, parseErr := strconv.ParseInt(s, 10, 64); parseErr == nil {
				rt.remaining.Store(v)
			}
		}
	}

	return response, err
}

type workaround struct {
	T http.RoundTripper
}

// RoundTrip workarounds missing content-type header when body is empty.
// This temporary workaround is needed as the recent go-openapi/runtime middleware
// won't send the content-type while the CrowdStrike service requires it for a time being
// https://github.com/go-openapi/runtime/commit/753b551e6b4a36e461ac877874fd0a79d0ffcf53
// Streaming session refresh within examples/falcon_event_stream can be used trigger this code.
func (w *workaround) RoundTrip(req *http.Request) (*http.Response, error) {
	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		req.Header.Add("Content-Type", "application/json")
	}
	return w.T.RoundTrip(req)
}

type retryTransport struct {
	T      http.RoundTripper
	config *RetryConfig

	mu            sync.Mutex
	cooldownUntil time.Time
}

func (rt *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response

	bo := &retryAfterBackOff{ExponentialBackOff: backoff.NewExponentialBackOff()}
	if rt.config.InitialInterval != 0 {
		bo.InitialInterval = rt.config.InitialInterval
	} else {
		bo.InitialInterval = 2 * time.Second
	}
	if rt.config.MaxInterval != 0 {
		bo.MaxInterval = rt.config.MaxInterval
	} else {
		bo.MaxInterval = time.Minute
	}

	operation := func() (*http.Response, error) {
		if err := rt.waitForCooldown(req.Context()); err != nil {
			return nil, backoff.Permanent(err)
		}

		cloned, err := cloneRequest(req)
		if err != nil {
			return nil, backoff.Permanent(fmt.Errorf("failed to clone request: %w", err))
		}

		resp, err := rt.T.RoundTrip(cloned)
		if err != nil {
			return resp, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			if wait := parseRetryAfter(resp.Header.Get("X-RateLimit-RetryAfter")); wait > 0 {
				bo.override = wait
				rt.setCooldown(wait)
			}
			log.Debugf("rate limited on %s, retrying", req.URL.Path)
			drainBody(resp)
			return nil, fmt.Errorf("retryable HTTP status: %d", resp.StatusCode)
		}

		if resp.StatusCode >= 500 {
			log.Debugf("retrying request to %s, status %d", req.URL.Path, resp.StatusCode)
			drainBody(resp)
			return nil, fmt.Errorf("retryable HTTP status: %d", resp.StatusCode)
		}

		return resp, nil
	}

	opts := []backoff.RetryOption{backoff.WithBackOff(bo)}
	if rt.config.MaxTries > 0 {
		opts = append(opts, backoff.WithMaxTries(rt.config.MaxTries))
	}

	resp, err := backoff.Retry(req.Context(), operation, opts...)
	return resp, err
}

// setCooldown updates the shared cooldown timestamp so subsequent requests
// wait before sending.
func (rt *retryTransport) setCooldown(d time.Duration) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	until := time.Now().Add(d)
	if until.After(rt.cooldownUntil) {
		rt.cooldownUntil = until
	}
}

// waitForCooldown blocks until the shared rate-limit cooldown expires or the
// context is cancelled.
func (rt *retryTransport) waitForCooldown(ctx context.Context) error {
	rt.mu.Lock()
	until := rt.cooldownUntil
	rt.mu.Unlock()

	wait := time.Until(until)
	if wait <= 0 {
		return nil
	}

	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		return fmt.Errorf("rate-limit cooldown (%s) exceeds context deadline: %w",
			wait.Round(time.Millisecond), context.DeadlineExceeded)
	}

	log.Debugf("waiting %s for rate-limit cooldown before sending request", wait.Round(time.Millisecond))
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	cloned := req.Clone(req.Context())

	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("failed to get request body: %w", err)
			}
			cloned.Body = body
		} else {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	return cloned, nil
}

func drainBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// retryAfterBackOff wraps ExponentialBackOff to honor X-RateLimit-RetryAfter on 429 responses.
type retryAfterBackOff struct {
	*backoff.ExponentialBackOff
	override time.Duration
}

// NextBackOff returns the override duration if set, otherwise delegates to exponential backoff.
func (b *retryAfterBackOff) NextBackOff() time.Duration {
	if b.override > 0 {
		d := min(b.override, b.MaxInterval)
		b.override = 0
		return d
	}
	return b.ExponentialBackOff.NextBackOff()
}

// parseRetryAfter parses the X-RateLimit-RetryAfter header (Unix epoch) and returns
// the duration to wait, with a minimum of 10 seconds. Returns 0 if the header is
// missing or unparseable.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}
	epoch, err := strconv.ParseInt(header, 10, 64)
	if err != nil {
		return 0
	}
	wait := time.Until(time.Unix(epoch, 0))
	if wait <= 0 {
		return 0
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

// TransportDecorator accepts a RoundTripper and returns a RoundTripper.
// This can be used to wrap or decorate the authenticated client's built-in
// HTTP client operation behavior for all API requests.
type TransportDecorator func(http.RoundTripper) http.RoundTripper
