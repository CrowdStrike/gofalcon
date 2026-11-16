package falcon

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

			newAutodiscoverClient(cfg)

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
		cli := newAutodiscoverClient(cfg)
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
