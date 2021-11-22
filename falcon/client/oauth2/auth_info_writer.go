package oauth2

import (
	"encoding/base64"
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

type revocationCreds string

func (creds revocationCreds) AuthenticateRequest(request runtime.ClientRequest, registry strfmt.Registry) error {
	return request.SetHeaderParam("Authorization", fmt.Sprintf("basic %s", creds))
}

func newRevocationCreds(client_id, client_secret string) revocationCreds {
	return revocationCreds(base64.StdEncoding.EncodeToString([]byte(client_id + ":" + client_secret)))
}

// AuthenticateRevocation supplies basic authentication to Oauth2RevokeToken method
func AuthenticateRevocation(clientId, clientSecret string) ClientOption {
	return func(op *runtime.ClientOperation) {
		op.AuthInfo = newRevocationCreds(clientId, clientSecret)
	}
}
