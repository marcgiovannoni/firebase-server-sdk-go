package firebase

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/oauth2"
)

const (
	authAPIEndpoint = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/"
	authAPITimeout  = time.Second * 10
)

var (
	errIllegalType = errors.New("error mismatch request/response type")
)

type validateFunc func(src interface{}) error

type apiSettings struct {
	method   string
	endpoint string
	reqFn    validateFunc
	respFn   validateFunc
}

var (
	errMissingRequestTarget = &APIError{
		Code:    AuthErrInternalError.Code,
		Message: "INTERNAL ASSERT FAILED: Server request is missing user identifier",
	}
	getAccountInfoAPI = &apiSettings{
		method:   "POST",
		endpoint: "getAccountInfo",
		reqFn: func(src interface{}) error {
			if r, ok := src.(*getAccountInfoRequest); !ok {
				return errIllegalType
			} else if s1, s2 := len(r.LocalID), len(r.Email); s1 == 0 && s2 == 0 {
				return errMissingRequestTarget
			}
			return nil
		},
		respFn: func(src interface{}) error {
			if r, ok := src.(*getAccountInfoResponse); !ok {
				return errIllegalType
			} else if len(r.Users) == 0 {
				return AuthErrUserNotFound
			}
			return nil
		},
	}
	deleteAccountAPI = &apiSettings{
		method:   "POST",
		endpoint: "deleteAccount",
		reqFn: func(src interface{}) error {
			if r, ok := src.(*deleteAccountRequest); !ok {
				return errIllegalType
			} else if r.LocalID == "" {
				return errMissingRequestTarget
			}
			return nil
		},
	}
	setAccountAPI = &apiSettings{
		method:   "POST",
		endpoint: "setAccountInfo",
		reqFn: func(src interface{}) error {
			r, ok := src.(map[string]interface{})
			if !ok {
				return errIllegalType
			} else if _, ok := r["localId"]; !ok {
				return errMissingRequestTarget
			}
			return validateCreateEditRequest(r)
		},
		respFn: func(src interface{}) error {
			if r, ok := src.(*createEditAccountResponse); !ok {
				return errIllegalType
			} else if r.LocalID == "" {
				return AuthErrUserNotFound
			}
			return nil
		},
	}
	signUpNewUserAPI = &apiSettings{
		method:   "POST",
		endpoint: "signupNewUser",
		reqFn: func(src interface{}) error {
			r, ok := src.(map[string]interface{})
			if !ok {
				return errIllegalType
			}
			return validateCreateEditRequest(r)
		},
		respFn: func(src interface{}) error {
			if r, ok := src.(*createEditAccountResponse); !ok {
				return errIllegalType
			} else if r.LocalID == "" {
				return &APIError{
					Code:    AuthErrInternalError.Code,
					Message: "INTERNAL ASSERT FAILED: Unable to create new user",
				}
			}
			return nil
		},
	}
)

type getAccountInfoRequest struct {
	LocalID []string `json:"localId,omitempty"`
	Email   []string `json:"email,omitempty"`
}

type getAccountInfoResponse struct {
	Users []*accountInfo `json:"users"`
}

type accountInfo struct {
	LocalID          string          `json:"localId"`
	Email            string          `json:"email"`
	EmailVerified    bool            `json:"emailVerified"`
	DisplayName      string          `json:"displayName"`
	PhotoURL         string          `json:"photoUrl"`
	Disabled         bool            `json:"disabled"`
	ValidSince       int64           `json:"validSince,string"`
	LastLoginAt      int64           `json:"lastLoginAt,string"`
	CreatedAt        int64           `json:"createdAt,string"`
	ProviderUserInfo []*providerInfo `json:"providerUserInfo"`
}

type providerInfo struct {
	RawID       string `json:"rawId"`
	FederatedID string `json:"federatedId"`
	ProviderID  string `json:"providerId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	PhotoURL    string `json:"photoUrl"`
}

func (h *requestHandler) getAccountByUID(uid string) (*UserRecord, error) {
	if !isValidUID(uid) {
		return nil, AuthErrInvalidUID
	}
	req := &getAccountInfoRequest{
		LocalID: []string{uid},
	}
	resp := new(getAccountInfoResponse)
	if err := h.call(getAccountInfoAPI, req, resp); err != nil {
		return nil, err
	}
	return newUserRecord(resp.Users[0])
}

func (h *requestHandler) getAccountByEmail(email string) (*UserRecord, error) {
	if !isValidEmail(email) {
		return nil, AuthErrInvalidEmail
	}
	req := &getAccountInfoRequest{
		Email: []string{email},
	}
	resp := new(getAccountInfoResponse)
	if err := h.call(getAccountInfoAPI, req, resp); err != nil {
		return nil, err
	}
	return newUserRecord(resp.Users[0])
}

func newUserRecord(info *accountInfo) (*UserRecord, error) {
	if info.LocalID == "" {
		return nil, &APIError{
			Code:    AuthErrInternalError.Code,
			Message: "INTERNAL ASSERT FAILED: Invalid user response",
		}
	}
	user := &UserRecord{
		UID:           info.LocalID,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		DisplayName:   info.DisplayName,
		PhotoURL:      info.PhotoURL,
		Disabled:      info.Disabled,
	}
	user.Metadata = &UserMetadata{
		CreatedAt:    parseDate(info.CreatedAt),
		LastSignedIn: parseDate(info.LastLoginAt),
	}
	user.ProviderData = make([]*UserInfo, len(info.ProviderUserInfo))
	for idx, val := range info.ProviderUserInfo {
		user.ProviderData[idx] = &UserInfo{
			UID:         val.RawID,
			DisplayName: val.DisplayName,
			Email:       val.Email,
			PhotoURL:    val.PhotoURL,
			ProviderID:  val.ProviderID,
		}
	}
	return user, nil
}

func parseDate(millis int64) time.Time {
	nano := millis * int64(time.Millisecond)
	return time.Unix(0, nano)
}

type deleteAccountRequest struct {
	LocalID string `json:"localId,omitempty"`
}

func (h *requestHandler) deleteAccount(uid string) error {
	if !isValidUID(uid) {
		return AuthErrInvalidUID
	}
	req := &deleteAccountRequest{
		LocalID: uid,
	}
	if err := h.call(deleteAccountAPI, req, &struct{}{}); err != nil {
		return err
	}
	return nil
}

var (
	errNullUserProperty = &APIError{
		Code:    AuthErrInvalidArgument.Code,
		Message: "Properties argument must be a non-nil instance.",
	}
	deletableParams = map[string]string{
		"displayName": "DISPLAY_NAME",
		"photoURL":    "PHOTO_URL",
	}
)

type createEditAccountResponse struct {
	LocalID string `json:"localId"`
}

func (h *requestHandler) updateExistingAccount(uid string, properties UserProperties) (string, error) {
	if !isValidUID(uid) {
		return "", AuthErrInvalidUID
	} else if properties == nil {
		return "", errNullUserProperty
	}
	req := make(map[string]interface{})
	for key, val := range properties {
		req[key] = val
	}
	req["localId"] = uid
	deleting := make([]string, 0, len(deletableParams))
	for key, param := range deletableParams {
		if val, ok := req[key]; ok && isEmptyValue(val) {
			deleting = append(deleting, param)
			delete(req, key)
		}
	}
	if len(deleting) > 0 {
		req["deleteAttribute"] = deleting
	}
	if val, ok := req["photoURL"]; ok {
		req["photoUrl"] = val
		delete(req, "photoURL")
	}
	if val, ok := req["disabled"]; ok {
		req["disableUser"] = val
		delete(req, "disabled")
	}
	resp := new(createEditAccountResponse)
	if err := h.call(setAccountAPI, req, resp); err != nil {
		return "", err
	}
	return resp.LocalID, nil
}

func (h *requestHandler) createNewAccount(properties UserProperties) (string, error) {
	if properties == nil {
		return "", errNullUserProperty
	}
	req := make(map[string]interface{})
	for key, val := range properties {
		req[key] = val
	}
	if val, ok := req["photoURL"]; ok {
		req["photoUrl"] = val
		delete(req, "photoURL")
	}
	if val, ok := req["uid"]; ok {
		req["localId"] = val
		delete(req, "uid")
	}
	resp := new(createEditAccountResponse)
	if err := h.call(signUpNewUserAPI, req, resp); err != nil {
		return "", err
	}
	return resp.LocalID, nil
}

type requestHandler struct {
	ts oauth2.TokenSource
}

func (h *requestHandler) getToken() (string, error) {
	t, err := h.ts.Token()
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

func buildHTTPRequest(api *apiSettings, src interface{}, tokenFunc func() (string, error)) (*http.Request, error) {
	srcBytes, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	endpoint := authAPIEndpoint + api.endpoint
	req, err := http.NewRequest(api.method, endpoint, bytes.NewBuffer(srcBytes))
	if err != nil {
		return nil, err
	}
	token, err := tokenFunc()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

type apiErrorResponse struct {
	RawServerError map[string]interface{} `json:"error"`
}

func getErrorResponse(resp *http.Response) error {
	if resp.StatusCode == 200 {
		return nil
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	res := new(apiErrorResponse)
	if err := json.Unmarshal(bodyBytes, res); err != nil {
		return fmt.Errorf("unmarshal error response failed: %v", err)
	}
	var errorCode string
	if res.RawServerError == nil {
		errorCode = ""
	} else if message, ok := res.RawServerError["message"]; !ok {
		errorCode = ""
	} else if errorCode, ok = message.(string); !ok {
		errorCode = ""
	}
	return authFromServerError(errorCode, res)
}

func loadHTTPResponse(resp *http.Response, dst interface{}) error {
	if err := getErrorResponse(resp); err != nil {
		return err
	} else if err = json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return err
	}
	return nil
}

func (h *requestHandler) call(api *apiSettings, src, dst interface{}) error {
	if api.reqFn != nil {
		if err := api.reqFn(src); err != nil {
			return err
		}
	}
	req, err := buildHTTPRequest(api, src, h.getToken)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), authAPITimeout)
	resp, err := ctxhttp.Do(ctx, nil, req)
	if err != nil {
		cancel()
		return err
	}
	defer resp.Body.Close()
	if err = loadHTTPResponse(resp, dst); err != nil {
		return err
	}
	if api.respFn != nil {
		if err = api.respFn(dst); err != nil {
			return err
		}
	}
	return nil
}

func isValidUID(uid string) bool {
	size := len(uid)
	return size > 0 && size <= 128
}

func isValidEmail(email string) bool {
	match, _ := regexp.MatchString("^[^@]+@[^@]+$", email)
	return match
}

func isValidPassword(password string) bool {
	size := len(password)
	return size >= 6
}

func isValidURL(urlString string) bool {
	dst, err := url.ParseRequestURI(urlString)
	if err != nil {
		return false
	}
	if scheme := dst.Scheme; scheme != "http" && scheme != "https" {
		return false
	}
	if match, _ := regexp.MatchString(`^[a-zA-Z0-9]+[\w\-]*([.]?[a-zA-Z0-9]+[\w\-]*)*(:\d{1,5})?$`, dst.Host); !match {
		return false
	}
	if path := dst.Path; path != "" && path != "/" {
		if match, _ := regexp.MatchString(`^(/[\w\-.~!$'()*+,;=:@]+)*$`, path); !match {
			return false
		}
	}
	return true
}

func isEmptyValue(val interface{}) bool {
	return reflect.DeepEqual(val, reflect.Zero(reflect.TypeOf(val)).Interface())
}

var (
	validCreateEditKeys = map[string]bool{
		"displayName":     true,
		"localId":         true,
		"email":           true,
		"password":        true,
		"rawPassword":     true,
		"emailVerified":   true,
		"photoUrl":        true,
		"disabled":        true,
		"disableUser":     true,
		"deleteAttribute": true,
		"sanityCheck":     true,
	}
)

func validateCreateEditRequest(r map[string]interface{}) error {
	for key := range r {
		if _, allowed := validCreateEditKeys[key]; !allowed {
			delete(r, key)
		}
	}
	if val, exists := r["displayName"]; exists {
		if _, ok := val.(string); !ok {
			return AuthErrInvalidDisplayName
		}
	}
	if val, exists := r["localId"]; exists {
		if uid, ok := val.(string); !ok || !isValidUID(uid) {
			return AuthErrInvalidUID
		}
	}
	if val, exists := r["email"]; exists {
		if email, ok := val.(string); !ok || !isValidEmail(email) {
			return AuthErrInvalidEmail
		}
	}
	if val, exists := r["password"]; exists {
		if pw, ok := val.(string); !ok || !isValidPassword(pw) {
			return AuthErrInvalidPassword
		}
	}
	if val, exists := r["rawPassword"]; exists {
		if pw, ok := val.(string); !ok || !isValidPassword(pw) {
			return AuthErrInvalidPassword
		}
	}
	if val, exists := r["emailVerified"]; exists {
		if _, ok := val.(bool); !ok {
			return AuthErrInvalidEmailVerified
		}
	}
	if val, exists := r["photoUrl"]; exists {
		if urlString, ok := val.(string); !ok || !isValidURL(urlString) {
			return AuthErrInvalidPhotoURL
		}
	}
	if val, exists := r["disabled"]; exists {
		if _, ok := val.(bool); !ok {
			return AuthErrInvalidDisabledField
		}
	}
	if val, exists := r["disableUser"]; exists {
		if _, ok := val.(bool); !ok {
			return AuthErrInvalidDisabledField
		}
	}
	return nil
}
