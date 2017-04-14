package firebase

import (
	"encoding/json"
	"fmt"
)

// The default auth errors definitions.
// For any advance information, see https://firebase.google.com/docs/auth/admin/errors
var (
	// AuthErrInvalidArgument represents the default api error that
	// an invalid argument was provided to an Authentication method.
	AuthErrInvalidArgument = &APIError{
		Code:    "auth/argument-error",
		Message: "Invalid argument provided.",
	}
	// AuthErrEmailAlreadyExists represents the default api error that
	// the provided email is already in use by an existing user.
	AuthErrEmailAlreadyExists = &APIError{
		Code:    "auth/email-already-exists",
		Message: "The email address is already in use by another account.",
	}
	// AuthErrInternalError represents the default api error that
	// the Authentication server encountered an unexpected error while
	// trying to process the request.
	AuthErrInternalError = &APIError{
		Code:    "auth/internal-error",
		Message: "An internal error has occurred.",
	}
	// AuthErrInvalidCredential represents the default api error that
	// the credential used to authenticate the Admin SDKs cannot be used
	// to perform the desired action.
	AuthErrInvalidCredential = &APIError{
		Code:    "auth/invalid-credential",
		Message: "Invalid credential object provided.",
	}
	// AuthErrInvalidDisabledField represents the default api error that
	// the provided value for the disabled user property is invalid
	AuthErrInvalidDisabledField = &APIError{
		Code:    "auth/invalid-disabled-field",
		Message: "The disabled field must be a boolean.",
	}
	// AuthErrInvalidDisplayName represents the default api error that
	// the provided value for the displayName user property is invalid
	AuthErrInvalidDisplayName = &APIError{
		Code:    "auth/invalid-display-name",
		Message: "The displayName field must be a valid string.",
	}
	// AuthErrInvalidEmailVerified represents the default api error that
	// the provided value for the emailVerified user property is invalid.
	AuthErrInvalidEmailVerified = &APIError{
		Code:    "auth/invalid-email-verified",
		Message: "The emailVerified field must be a boolean.",
	}
	// AuthErrInvalidEmail represents the default api error that
	// the provided value for the email user property is invalid
	AuthErrInvalidEmail = &APIError{
		Code:    "auth/invalid-email",
		Message: "The email address is improperly formatted.",
	}
	// AuthErrInvalidPassword represents the default api error that
	// the provided value for the password user property is invalid.
	AuthErrInvalidPassword = &APIError{
		Code:    "auth/invalid-password",
		Message: "The password must be a string with at least 6 characters.",
	}
	// AuthErrInvalidPhotoURL represents the default api error that
	// the provided value for the photoURL user property is invalid.
	AuthErrInvalidPhotoURL = &APIError{
		Code:    "auth/invalid-photo-url",
		Message: "The photoURL field must be a valid URL.",
	}
	// AuthErrInvalidUID represents the default api error that the provided uid is invalid.
	// It must be a non-empty string with at most 128 characters.
	AuthErrInvalidUID = &APIError{
		Code:    "auth/invalid-uid",
		Message: "The uid must be a non-empty string with at most 128 characters.",
	}
	// AuthErrMissingUID represents the default api error that
	// a uid identifier is required for the current operation.
	AuthErrMissingUID = &APIError{
		Code:    "auth/missing-uid",
		Message: "A uid identifier is required for the current operation.",
	}
	// AuthErrOperationNotAllowed represents the default api error that
	// the provided sign-in provider is disabled for your Firebase project.
	AuthErrOperationNotAllowed = &APIError{
		Code: "auth/operation-not-allowed",
		Message: `The given sign-in provider is disabled for this Firebase project.
		Enable it in the Firebase console, under the sign-in method tab of the Auth section.`,
	}
	// AuthErrProjectNotFound represents the default api error that
	// no Firebase project was found for the credential used to initialize the SDK.
	AuthErrProjectNotFound = &APIError{
		Code:    "auth/project-not-found",
		Message: "No Firebase project was found for the provided credential.",
	}
	// AuthErrInsufficientPermission represents the default api error that
	// the credential used to initialize the SDK has insufficient permission
	// to access the requested Authentication resource.
	AuthErrInsufficientPermission = &APIError{
		Code: "auth/insufficient-permission",
		Message: `Credential implementation provided to initializeApp() via the "credential" property has insufficient permission to access the requested resource.
		 See https://firebase.google.com/docs/admin/setup for details on how to authenticate this SDK with appropriate permissions.
		 `,
	}
	// AuthErrUIDAlreadyExists represents the default api error that
	// the provided uid is already in use by an existing user.
	AuthErrUIDAlreadyExists = &APIError{
		Code:    "auth/uid-already-exists",
		Message: "The user with the provided uid already exists.",
	}
	// AuthErrUserNotFound represents the default api error that
	// there is no existing user record corresponding to the provided identifier.
	AuthErrUserNotFound = &APIError{
		Code:    "auth/user-not-found",
		Message: "There is no user record corresponding to the provided identifier.",
	}
)

var (
	authServerToClientCodes = map[string]*APIError{
		// Project not found.
		"CONFIGURATION_NOT_FOUND": AuthErrProjectNotFound,
		// Provided credential has insufficient permissions.
		"INSUFFICIENT_PERMISSION": AuthErrInsufficientPermission,
		// uploadAccount provides an email that already exists.
		"DUPLICATE_EMAIL": AuthErrEmailAlreadyExists,
		// uploadAccount provides a localId that already exists.
		"DUPLICATE_LOCAL_ID": AuthErrUIDAlreadyExists,
		// setAccountInfo email already exists.
		"EMAIL_EXISTS": AuthErrEmailAlreadyExists,
		// Invalid email provided.
		"INVALID_EMAIL": AuthErrInvalidEmail,
		// No localId provided (deleteAccount missing localId).
		"MISSING_LOCAL_ID": AuthErrMissingUID,
		// Empty user list in uploadAccount.
		"MISSING_USER_ACCOUNT": AuthErrMissingUID,
		// Password auth disabled in console.
		"OPERATION_NOT_ALLOWED": AuthErrOperationNotAllowed,
		// Project not found.
		"PROJECT_NOT_FOUND": AuthErrProjectNotFound,
		// User on which action is to be performed is not found.
		"USER_NOT_FOUND": AuthErrUserNotFound,
		// Password provided is too weak.
		"WEAK_PASSWORD": AuthErrInvalidPassword,
	}
)

func authFromServerError(errorCode string, raw interface{}) error {
	err, ok := authServerToClientCodes[errorCode]
	if !ok {
		err = AuthErrInternalError
	}
	if err.Code == AuthErrInternalError.Code && raw != nil {
		if rawBytes, _ := json.Marshal(raw); len(rawBytes) > 0 {
			err.Message = fmt.Sprintf("%s Raw server response \"%s\"", err.Message, string(rawBytes))
		}
	}
	return err
}

// APIError defines the data model of Firebase API errors.
type APIError struct {
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("code: %s, message: %s", e.Code, e.Message)
}
