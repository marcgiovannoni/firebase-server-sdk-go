package firebase

import (
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

var authInstances = struct {
	sync.Mutex
	m map[string]*Auth
}{
	m: make(map[string]*Auth),
}

// Auth is the entry point for all server-side Firebase Authentication actions.
//
// You can get an instance of Auth via GetInstance(*App) and then use it to
// perform a variety of authentication-related operations, including generating
// custom tokens for use by client-side code, verifying Firebase ID Tokens
// received from clients, or creating new App instances that are scoped to a
// particular authentication UID.
type Auth struct {
	app *App
	ts  oauth2.TokenSource
}

// GetAuth gets the Auth instance for the default App.
func GetAuth() (*Auth, error) {
	app, err := GetApp()
	if err != nil {
		return nil, err
	}
	return GetAuthWithApp(app)
}

// GetAuthWithApp gets an instance of Auth for a specific App.
func GetAuthWithApp(app *App) (*Auth, error) {
	appName := app.name
	authInstances.Lock()
	defer authInstances.Unlock()
	if _, ok := authInstances.m[appName]; !ok {
		authInstances.m[appName] = &Auth{app: app}
	}
	return authInstances.m[appName], nil
}

// CreateCustomToken creates a Firebase Custom Token associated with the given
// UID and additionally containing the specified developerClaims.  This token
// can then be provided back to a client application for use with the
// signInWithCustomToken authentication API.
//
// The UID identifies the user to other Firebase services (Firebase Database,
// Storage, etc.) and should be less than 128 characters.
// The developer claims are optional, additional claims to be stored in the
// token.  The claims must be serializable to JSON.
func (a *Auth) CreateCustomToken(uid string, developerClaims *Claims) (string, error) {
	if err := a.app.options.ensureServiceAccount(); err != nil {
		return "", err
	}
	c := a.app.options.ServiceAccountCredential
	return createSignedCustomAuthTokenForUser(uid, developerClaims, c.ClientEmail, c.PrivateKey)
}

// VerifyIDToken parses and verifies a Firebase ID Token.
//
// A Firebase application can identify itself to a trusted backend server by
// sending its Firebase ID Token (accessible via the getToken API in the
// Firebase Authentication client) with its request.
//
// The backend server can then use the VerifyIDToken() method to verify the
// token is valid, meaning: the token is properly signed, has not expired,
// and it was issued for the project associated with this Auth instance
// (which by default is extracted from your service account).
func (a *Auth) VerifyIDToken(tokenString string) (*Token, error) {
	return a.VerifyIDTokenWithTransport(tokenString, nil)
}

// VerifyIDToken parses and verifies a Firebase ID Token.
//
// Same as VerifyIDToken but with the possibility to define the Transport to be use by http.Client
// This have to be use in Google App Engine standard environment with the fetchUrl transport.
func (a *Auth) VerifyIDTokenWithTransport(tokenString string, transport http.RoundTripper) (*Token, error) {
	if err := a.app.options.ensureServiceAccount(); err != nil {
		return nil, err
	}
	projectID := a.app.options.ServiceAccountCredential.ProjectID
	return verify(projectID, tokenString, transport)
}

// GetUser looks up the user identified by the provided user id and
// returns a user record for the given user if that user is found.
func (auth *Auth) GetUser(uid string) (*UserRecord, error) {
	if err := ensureTokenSource(auth); err != nil {
		return nil, err
	}
	handler := &requestHandler{ts: auth.ts}
	return handler.getAccountByUID(uid)
}

// GetUserByEmail looks up the user identified by the provided email and
// returns a user record for the given user if that user is found.
func (auth *Auth) GetUserByEmail(email string) (*UserRecord, error) {
	if err := ensureTokenSource(auth); err != nil {
		return nil, err
	}
	handler := &requestHandler{ts: auth.ts}
	return handler.getAccountByEmail(email)
}

// CreateUser creates a new user with the properties provided.
func (auth *Auth) CreateUser(properties UserProperties) (*UserRecord, error) {
	if err := ensureTokenSource(auth); err != nil {
		return nil, err
	}
	handler := &requestHandler{ts: auth.ts}
	uid, err := handler.createNewAccount(properties)
	if err != nil {
		return nil, err
	}
	return handler.getAccountByUID(uid)
}

// DeleteUser deletes the user identified by the provided user id and returns
// nil error when the user is found and successfully deleted.
func (auth *Auth) DeleteUser(uid string) error {
	if err := ensureTokenSource(auth); err != nil {
		return err
	}
	handler := &requestHandler{ts: auth.ts}
	return handler.deleteAccount(uid)
}

// UpdateUser updates an existing user with the properties provided.
func (auth *Auth) UpdateUser(uid string, properties UserProperties) (*UserRecord, error) {
	if err := ensureTokenSource(auth); err != nil {
		return nil, err
	}
	handler := &requestHandler{ts: auth.ts}
	uid, err := handler.updateExistingAccount(uid, properties)
	if err != nil {
		return nil, err
	}
	return handler.getAccountByUID(uid)
}
