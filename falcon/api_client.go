package falcon

import (
	"bytes"
	"context"
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
	customTransport.Consumers["application/pdf"] = httpruntime.ByteStreamConsumer()
	customTransport.Consumers["application/x-7z-compressed"] = httpruntime.ByteStreamConsumer()

	return client.New(customTransport, strfmt.Default), nil
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
	return commonHTTPClientConfig(oauth2.NewClient(ac.Context, ts), ac)
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
	return commonHTTPClientConfig(config.Client(ac.Context), ac)
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
