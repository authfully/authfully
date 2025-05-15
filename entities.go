package authfully

// User is an interface that represents a user in the system.
type User interface {
	// GetID returns the ID of the user.
	GetID() string

	// CheckPassword checks if the given password is valid for the user.
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
	// GetID returns the ID of the client.
	GetID() string

	// GetName returns the human-readable name of the client.
	GetName() string

	// CheckSecret check the given secret string against the client
	// to see if it is valid.
	CheckSecret(secret string) error

	// CheckRedirectURIs checks if the redirect URI matches the supposed redirect URI.
	CheckRedirectURI(redirectURI string) error

	// CheckScope checks if all the requested scopes are valid for the client.
	CheckScope(scope string) error
}

// ClientStore is an interface that defines methods for client storage and retrieval.
type ClientStore interface {
	GetClientByID(id string) (Client, error)
}

// TokenSessionRequest represents a request to create a new token session.
type TokenSessionRequest struct {
	// GrantType is the type of grant being requested.
	GrantType string `json:"grant_type,omitempty"`

	// ClientID is the ID of the client making the request.
	ClientID string `json:"client_id,omitempty"`

	// Code is the authorization code received from the authorization server.
	Code string `json:"code,omitempty"`

	// CodeChallenge is the code challenge used for PKCE (Proof Key for Code Exchange).
	CodeChallenge string `json:"code_challenge,omitempty"`

	// CodeChallengeMethod is the code challenge method used for PKCE (Proof Key for Code Exchange).
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// Scope is the scope of the access request.
	Scope string `json:"scope,omitempty"`
}

// PendingTokenSession is an interface that represents a pending token session in the system.
// It is used to store the authorization code and other information
// before the token session is authorized by user.
type PendingTokenSession interface {
	// GetID returns the ID of the token session.
	GetID() string

	// GetGrantType returns the grant type of the token session.
	GetGrantType() string

	// GetClientID returns the client ID of the token session.
	GetClientID() string

	// GetUserID returns the user ID of the token session.
	GetUserID() string

	// GetCode returns the authorization code of the token session.
	GetCode() string

	// GetCodeChallenge returns the code challenge of the token session.
	GetCodeChallenge() string

	// GetCodeChallengeMethod returns the code challenge method of the token session.
	GetCodeChallengeMethod() string

	// GetTokenType returns the token type of the token session.
	GetTokenType() string

	// GetScope returns the scopes of the token session.
	GetScope() string

	// GetState returns the state of the token session.
	GetState() string
}

// TokenSession is an interface that represents a token session in the system.
type TokenSession interface {

	// GetID returns the ID of the token session.
	GetID() string

	// GetGrantType returns the grant type of the token session.
	GetGrantType() string

	// GetClientID returns the client ID of the token session.
	GetClientID() string

	// GetUserID returns the user ID of the token session.
	GetUserID() string

	// GetTokenType returns the token type of the token session.
	GetTokenType() string

	// GetAccessToken returns the access token of the token session.
	GetAccessToken() string

	// GetRefreshToken returns the refresh token of the token session.
	GetRefreshToken() string

	// GetAccessTokenExpiry returns the access token expiry time of the token session.
	// It is in Unix timestamp format.
	GetAccessTokenExpiry() int64

	// GetScope returns the scopes of the token session.
	GetScope() string

	// IsRevoked checks if the token session is revoked.
	IsRevoked() bool
}

// TokenSessionStore is an interface that defines methods for token session storage and retrieval.
type TokenSessionStore interface {

	// GetPendingTokenSessionByID retrieves a pending token session by its ID.
	CreatePendingTokenSession(req *TokenSessionRequest) (PendingTokenSession, error)

	// GetTokenSessionByID retrieves a token session by its ID.
	GetPendingTokenSessionByID(id string) (PendingTokenSession, error)

	// PromotePendingTokenSession creates a new token session.
	PromotePendingTokenSession(pendingTokenSession PendingTokenSession) (TokenSession, error)

	// GetTokenSessionByID retrieves a token session by its ID.
	GetTokenSessionByID(id string) (TokenSession, error)

	// GetTokenSessionByCode retrieves a token session by its authorization code.
	GetTokenSessionByCode(code string) (TokenSession, error)

	// GetTokenSessionByAccessToken retrieves a token session by its access token.
	GetTokenSessionByAccessToken(accessToken string) (TokenSession, error)

	// GetTokenSessionByRefreshToken retrieves a token session by its refresh token.
	GetTokenSessionByRefreshToken(refreshToken string) (TokenSession, error)

	// RevokeTokenSession revokes a token session by its ID.
	RevokeTokenSession(id string) error
}
