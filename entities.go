package authfully

// User is an interface that represents a user in the system.
type User interface {
	CheckPassword(password string) error
}

// UserStore is an interface that defines methods for user storage and retrieval.
type UserStore interface {
	// GetUserByID retrieves a user by their ID.
	GetUserByID(id string) (User, error)

	// GetUserByEmail retrieves a user by their email address, user name, or any
	// valid identifier used for the login process.
	GetUserByLoginName(loginName string) (User, error)
}

// Client is an OAuth 2.0 client interface.
type Client interface {
	// CheckSecret check the given secret string against the client
	// to see if it is valid.
	CheckSecret(secret string) error

	// CheckRedirectURIs checks if the redirect URI matches the supposed redirect URI.
	CheckRedirectURI(redirectURI string) error

	// CheckScopes checks if all the requested scopes are valid for the client.
	CheckScopes(scopes []string) error
}

// ClientStore is an interface that defines methods for client storage and retrieval.
type ClientStore interface {
	GetClientByID(id string) (Client, error)
}
