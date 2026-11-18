package falcon

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/oauth2"
	"github.com/go-openapi/runtime/logger"
	"github.com/go-openapi/runtime/middleware"
)

// captureStderr returns everything written to os.Stderr while fn runs.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()

	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	return <-out
}

// TestNewAutodiscoverClientSetsGlobalLoggerOnlyInDebug verifies that building
// an autodiscovery client replaces go-openapi's package-wide middleware logger
// only when debug output is enabled, so normal runs leave it untouched.
func TestNewAutodiscoverClientSetsGlobalLoggerOnlyInDebug(t *testing.T) {
	cfg := &client.TransportConfig{
		Host:     "127.0.0.1",
		BasePath: "/",
		Schemes:  []string{"http"},
	}

	tests := []struct {
		name          string
		debug         string
		wantRedacting bool
	}{
		{name: "debug off", debug: "", wantRedacting: false},
		{name: "debug on", debug: "1", wantRedacting: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// go-openapi reads both variables when the runtime is constructed.
			t.Setenv("DEBUG", tc.debug)
			t.Setenv("SWAGGER_DEBUG", "")

			orig := middleware.Logger
			t.Cleanup(func() { middleware.Logger = orig })
			middleware.Logger = logger.StandardLogger{}

			newAutodiscoverClient(cfg, nil)

			_, gotRedacting := middleware.Logger.(redactingLogger)
			if gotRedacting != tc.wantRedacting {
				t.Errorf("middleware.Logger is %T, want redactingLogger installed = %v", middleware.Logger, tc.wantRedacting)
			}
		})
	}
}

// TestAutodiscoverClientRedactsSecretsInDebugOutput verifies that when the
// go-openapi DEBUG switch is on, the token and revoke requests made during
// cloud autodiscovery are still dumped for troubleshooting, but the client
// secret never appears in the output, either as a form field or inside the
// Basic authorization header.
func TestAutodiscoverClientRedactsSecretsInDebugOutput(t *testing.T) {
	const (
		clientID     = "my-client-id"
		clientSecret = "my-super-secret-value"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			w.Header().Set("X-Cs-Region", "us-2")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":1799,"token_type":"bearer"}`)
		case "/oauth2/revoke":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"meta":{},"errors":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// go-openapi reads DEBUG when the runtime is constructed.
	t.Setenv("DEBUG", "1")

	cfg := &client.TransportConfig{
		Host:     strings.TrimPrefix(srv.URL, "http://"),
		BasePath: "/",
		Schemes:  []string{"http"},
	}

	output := captureStderr(t, func() {
		cli := newAutodiscoverClient(cfg, nil)
		ctx := context.Background()

		token, err := cli.Oauth2.Oauth2AccessToken(&oauth2.Oauth2AccessTokenParams{
			Context:      ctx,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
		if err != nil {
			t.Errorf("Oauth2AccessToken: %v", err)
			return
		}

		_, err = cli.Oauth2.Oauth2RevokeToken(&oauth2.Oauth2RevokeTokenParams{
			Context: ctx,
			Token:   token.Payload.AccessToken,
		}, oauth2.AuthenticateRevocation(clientID, clientSecret))
		if err != nil {
			t.Errorf("Oauth2RevokeToken: %v", err)
		}
	})

	// Debug output must still be useful for troubleshooting.
	for _, want := range []string{"POST /oauth2/token", "POST /oauth2/revoke", "client_id=" + clientID} {
		if !strings.Contains(output, want) {
			t.Errorf("debug output missing %q; got:\n%s", want, output)
		}
	}

	// The secret must not leak in any form.
	basicCreds := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	for _, leaked := range []string{clientSecret, basicCreds} {
		if strings.Contains(output, leaked) {
			t.Errorf("debug output leaked %q; got:\n%s", leaked, output)
		}
	}
}

// scriptedOAuthServer answers each /oauth2 path with the status codes queued
// for it, then with success, and records the body of every request.
type scriptedOAuthServer struct {
	mu       sync.Mutex
	statuses map[string][]int
	bodies   map[string][]string
}

func newScriptedOAuthServer(t *testing.T, statuses map[string][]int) (*scriptedOAuthServer, *client.TransportConfig) {
	t.Helper()
	s := &scriptedOAuthServer{statuses: statuses, bodies: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	return s, &client.TransportConfig{
		Host:     strings.TrimPrefix(srv.URL, "http://"),
		BasePath: "/",
		Schemes:  []string{"http"},
	}
}

func (s *scriptedOAuthServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.bodies[r.URL.Path] = append(s.bodies[r.URL.Path], string(body))
	status := 0
	if queued := s.statuses[r.URL.Path]; len(queued) > 0 {
		status, s.statuses[r.URL.Path] = queued[0], queued[1:]
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch {
	case status != 0:
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"meta":{},"errors":[]}`)
	case r.URL.Path == "/oauth2/token":
		w.Header().Set("X-Cs-Region", "us-2")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":1799,"token_type":"bearer"}`)
	default:
		_, _ = io.WriteString(w, `{"meta":{},"errors":[]}`)
	}
}

// requests returns the bodies received so far on path.
func (s *scriptedOAuthServer) requests(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.bodies[path]...)
}

// TestAutodiscoverClientRetries verifies that the autodiscovery client retries
// transient token and revoke failures when given a RetryConfig, sends the
// credentials again on every attempt, and leaves rejected credentials alone.
func TestAutodiscoverClientRetries(t *testing.T) {
	t.Parallel()
	const (
		clientID     = "my-client-id"
		clientSecret = "my-super-secret-value"
	)

	tests := []struct {
		name        string
		retry       *RetryConfig
		statuses    map[string][]int
		wantErr     bool
		wantTokens  int
		wantRevokes int
	}{
		{
			name:       "no retry config fails on the first 503",
			statuses:   map[string][]int{"/oauth2/token": {503}},
			wantErr:    true,
			wantTokens: 1,
		},
		{
			name:        "retries token 5xx until it succeeds",
			retry:       fastRetry(5),
			statuses:    map[string][]int{"/oauth2/token": {503, 502}},
			wantTokens:  3,
			wantRevokes: 1,
		},
		{
			name:        "retries token 429",
			retry:       fastRetry(5),
			statuses:    map[string][]int{"/oauth2/token": {429}},
			wantTokens:  2,
			wantRevokes: 1,
		},
		{
			name:       "does not retry rejected credentials",
			retry:      fastRetry(5),
			statuses:   map[string][]int{"/oauth2/token": {401}},
			wantErr:    true,
			wantTokens: 1,
		},
		{
			name:       "stops after MaxTries",
			retry:      fastRetry(3),
			statuses:   map[string][]int{"/oauth2/token": {503, 503, 503, 503}},
			wantErr:    true,
			wantTokens: 3,
		},
		{
			name:        "retries revoke 5xx",
			retry:       fastRetry(5),
			statuses:    map[string][]int{"/oauth2/revoke": {503}},
			wantTokens:  1,
			wantRevokes: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, cfg := newScriptedOAuthServer(t, tc.statuses)
			cli := newAutodiscoverClient(cfg, tc.retry)
			ctx := context.Background()

			token, err := cli.Oauth2.Oauth2AccessToken(&oauth2.Oauth2AccessTokenParams{
				Context:      ctx,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			})
			if err == nil {
				_, err = cli.Oauth2.Oauth2RevokeToken(&oauth2.Oauth2RevokeTokenParams{
					Context: ctx,
					Token:   token.Payload.AccessToken,
				}, oauth2.AuthenticateRevocation(clientID, clientSecret))
			}

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("error = %v, want error = %v", err, tc.wantErr)
			}
			tokens := srv.requests("/oauth2/token")
			if len(tokens) != tc.wantTokens {
				t.Errorf("token requests = %d, want %d", len(tokens), tc.wantTokens)
			}
			for i, body := range tokens {
				if !strings.Contains(body, "client_secret="+clientSecret) {
					t.Errorf("token attempt %d lost the client secret, body %q", i+1, body)
				}
			}
			revokes := srv.requests("/oauth2/revoke")
			if len(revokes) != tc.wantRevokes {
				t.Errorf("revoke requests = %d, want %d", len(revokes), tc.wantRevokes)
			}
			for i, body := range revokes {
				if body != "token=tok" {
					t.Errorf("revoke attempt %d body = %q, want %q", i+1, body, "token=tok")
				}
			}
		})
	}
}
