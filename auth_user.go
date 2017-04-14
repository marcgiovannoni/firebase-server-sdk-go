package firebase

import (
	"time"
)

// UserRecord defines the data model for Firebase interface representing a user.
type UserRecord struct {
	UID           string
	DisplayName   string
	Email         string
	EmailVerified bool
	PhotoURL      string
	ProviderData  []*UserInfo
	Disabled      bool
	Metadata      *UserMetadata
}

// UserInfo defines the data model for Firebase interface representing a user's info from a third-party
// identity provider such as Google or Facebook.
type UserInfo struct {
	UID         string
	ProviderID  string
	DisplayName string
	Email       string
	PhotoURL    string
}

// UserMetadata defines the data model for Firebase interface representing a user's metadata.
type UserMetadata struct {
	CreatedAt    time.Time
	LastSignedIn time.Time
}

// UserProperties defines the input user properties in a create or edit user API.
//
// Note that user attributes without setup in create actions will remain in default values.
// And attributes without setup in edit actions are remaining unchanged.
type UserProperties map[string]interface{}

// SetUID sets the uid to assign to the newly created user.
// Must be a string between 1 and 128 characters long, inclusive.
// If not provided, a random uid will be automatically generated.
//
// Note that this property takes no effects in update user actions.
func (p UserProperties) SetUID(uid string) UserProperties {
	p["uid"] = uid
	return p
}

// SetEmail sets the user's primary email. Must be a valid email address.
func (p UserProperties) SetEmail(email string) UserProperties {
	p["email"] = email
	return p
}

// SetEmailVerified sets whether or not the user's primary email is verified.
func (p UserProperties) SetEmailVerified(emailVerified bool) UserProperties {
	p["emailVerified"] = emailVerified
	return p
}

// SetPassword sets the user's raw, unhashed password.
// Must be at least six characters long.
func (p UserProperties) SetPassword(password string) UserProperties {
	p["password"] = password
	return p
}

// SetDisplayName sets the users' display name.
// Only passing an empty string in edit actions removes the display name in the user record.
func (p UserProperties) SetDisplayName(displayName string) UserProperties {
	p["displayName"] = displayName
	return p
}

// SetPhotoURL sets the user's photo URL.
// Only passing an empty string in edit actions removes the photo URL in the user record.
func (p UserProperties) SetPhotoURL(photoURL string) UserProperties {
	p["photoURL"] = photoURL
	return p
}

// SetDisabled sets whether or not the user is disabled
func (p UserProperties) SetDisabled(disabled bool) UserProperties {
	p["disabled"] = disabled
	return p
}
