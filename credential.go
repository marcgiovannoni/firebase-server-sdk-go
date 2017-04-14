package firebase

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"

	"github.com/SermoDigital/jose/crypto"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/jwt"
)

// GoogleServiceAccountCredential is the credential for a GCP Service Account.
type GoogleServiceAccountCredential struct {
	// ProjectID is the project ID.
	ProjectID string
	// PrivateKey is the RSA256 private key.
	PrivateKey *rsa.PrivateKey
	// PrivateKeyString is the private key represented in string.
	PrivateKeyString string
	// ClientEmail is the client email.
	ClientEmail string
}

// UnmarshalJSON is the custom unmarshaler for GoogleServiceAccountCredential.
// Private key is parsed from PEM format.
func (c *GoogleServiceAccountCredential) UnmarshalJSON(data []byte) error {
	var aux struct {
		ProjectID   string `json:"project_id"`
		PrivateKey  string `json:"private_key"`
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	privKey, err := crypto.ParseRSAPrivateKeyFromPEM([]byte(aux.PrivateKey))
	if err != nil {
		return err
	}
	c.PrivateKey = privKey
	c.PrivateKeyString = aux.PrivateKey

	c.ProjectID = aux.ProjectID
	c.ClientEmail = aux.ClientEmail
	return nil
}

// loadCredential loads the Service Account credential from a JSON file.
func loadCredential(r io.Reader) (*GoogleServiceAccountCredential, error) {
	var c GoogleServiceAccountCredential
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

const (
	// jwtTokenURL is Google's OAuth 2.0 token URL to use with the JWT flow.
	jwtTokenURL = "https://accounts.google.com/o/oauth2/token"
)

var (
	scopes = []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/firebase.database",
		"https://www.googleapis.com/auth/firebase.messaging",
		"https://www.googleapis.com/auth/identitytoolkit",
	}
)

func ensureTokenSource(auth *Auth) error {
	if auth.ts != nil {
		return nil
	}
	cred := auth.app.options.ServiceAccountCredential
	if cred == nil {
		return errors.New("no service account credential found")
	}

	cfg := &jwt.Config{
		Email:      cred.ClientEmail,
		PrivateKey: []byte(cred.PrivateKeyString),
		Scopes:     append([]string{}, scopes...),
		TokenURL:   jwtTokenURL,
	}
	auth.ts = cfg.TokenSource(context.TODO())
	return nil
}
