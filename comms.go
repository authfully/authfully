package authfully

import (
	"fmt"
	"net/url"
)

// AuthorizationRequest represents an OAuth 2.0 authorization request.
//
// References:
// - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
// - https://www.oauth.com/oauth2-servers/pkce/authorization-request/
type AuthorizationRequest struct {
	ResponseType string `json:"response_type,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	State        string `json:"state,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// CodeChallenge is used for PKCE (Proof Key for Code Exchange)
	CodeChallenge string `json:"code_challenge,omitempty"`

	// CodeChallengeMethod is used for PKCE (Proof Key for Code Exchange)
	// It can be "plain" or "S256".
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// AuthorizationResponse represents an OAuth 2.0 authorization response.
//
// References:
// - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
// - https://www.oauth.com/oauth2-servers/pkce/authorization-response/
type AuthorizationResponse struct {

	// ResponseType repeats the response_type of the request.
	ResponseType string `json:"response_type,omitempty"`

	// For authorization code flow, the authorization code is returned in the URL query.
	Code string `json:"code,omitempty"`

	// For authorization code flow, the state is returned in the URL query.
	State string `json:"state,omitempty"`

	// For implicit flow, the access token is returned in the URL fragment.
	AccessTokenResponse *AccessTokenResponse `json:"-"`

	// For implicit flow, the access token error is returned in the URL fragment.
	AccessTokenErrorResponse *AccessTokenErrorResponse `json:"-"`
}

// ToQueryValues converts the AuthorizationResponse to a url.Values to
// be easily converted to URL encoded query string.
func (resp AuthorizationResponse) ToQueryValues() url.Values {
	v := url.Values{}

	// If the response is an access token response, use that.
	if resp.AccessTokenResponse != nil {
		return resp.AccessTokenResponse.ToQueryValues()
	}

	// If the response is an access token error response, use that.
	if resp.AccessTokenErrorResponse != nil {
		return resp.AccessTokenErrorResponse.ToQueryValues()
	}

	// Otherwise, use the authorization response values.
	if resp.ResponseType != "" {
		v.Set("response_type", resp.ResponseType)
	}
	if resp.Code != "" {
		v.Set("code", resp.Code)
	}
	if resp.State != "" {
		v.Set("state", resp.State)
	}
	return v
}

// AuthorizationErrorResponse represents an OAuth 2.0 authorization error response.
type AuthorizationErrorResponse struct {
	// Error is an optional error string.
	// It is used when the authorization request fails.
	// It can be "invalid_request", "unauthorized_client", "access_denied",
	// "unsupported_response_type", "invalid_scope", "server_error", or "temporarily_unavailable".
	//
	// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	ErrorType string `json:"error,omitempty"`

	// ErrorDescription is an optional error description.
	ErrorDescription string `json:"error_description,omitempty"`

	// ErrorURI is an optional error URI.
	ErrorURI string `json:"error_uri,omitempty"`
}

// Error implements the error interface for AuthorizationErrorResponse.
func (e AuthorizationErrorResponse) Error() string {
	// Remove underscores of the .Error field
	// to make it more user-friendly.
	msg := e.ErrorDescription
	if msg == "" {
		switch e.ErrorType {
		case "invalid_request":
			msg = "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
		case "unauthorized_client":
			msg = "The client is not authorized to request an authorization code using this method."
		case "access_denied":
			msg = "The resource owner or authorization server denied the request."
		case "unsupported_response_type":
			msg = "The authorization server does not support obtaining an authorization code using this method."
		case "invalid_scope":
			msg = "The requested scope is invalid, unknown, or malformed."
		case "server_error":
			msg = "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."
		case "temporarily_unavailable":
			msg = "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
		}
	}

	return fmt.Sprintf("OAuth2 error (%s): %s", e.ErrorType, msg)
}

// ToQueryValues converts the AuthorizationErrorResponse to a url.Values to
// be easily converted to URL encoded query string.
func (e AuthorizationErrorResponse) ToQueryValues() url.Values {
	v := url.Values{}
	if e.ErrorType != "" {
		v.Set("error", e.ErrorType)
	}
	if e.ErrorDescription != "" {
		v.Set("error_description", e.ErrorDescription)
	}
	if e.ErrorURI != "" {
		v.Set("error_uri", e.ErrorURI)
	}
	return v
}

// AccessTokenRequest represents an OAuth 2.0 token request.
//
// Represets any request to the token endpoint.
//
// References:
// - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// - https://www.oauth.com/oauth2-servers/pkce/authorization-code-exchange/
type AccessTokenRequest struct {
	GrantType    string `json:"grant_type,omitempty"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`

	// CodeVerifier is used for PKCE (Proof Key for Code Exchange)
	// It is the original code verifier used to generate the code challenge.
	CodeVerifier string `json:"code_verifier,omitempty"`
}

// AccessTokenResponse represents an OAuth 2.0 token response.
// Can be used for either:
//  1. access token responses
//     (for token endpoint, or for auth endpoint in implicit flow); or
//  2. refresh token responses; or
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`
}

// ToQueryValues converts the AccessTokenResponse to a url.Values to
// be easily converted to URL encoded query string.
func (resp AccessTokenResponse) ToQueryValues() url.Values {
	v := url.Values{}
	if resp.AccessToken != "" {
		v.Set("access_token", resp.AccessToken)
	}
	if resp.RefreshToken != "" {
		v.Set("refresh_token", resp.RefreshToken)
	}
	if resp.ExpiresIn != 0 {
		v.Set("expires_in", fmt.Sprintf("%d", resp.ExpiresIn))
	}
	if resp.TokenType != "" {
		v.Set("token_type", resp.TokenType)
	}
	if resp.Scope != "" {
		v.Set("scope", resp.Scope)
	}
	if resp.State != "" {
		v.Set("state", resp.State)
	}
	return v
}

// AccessTokenErrorResponse represents an OAuth 2.0 token error response.
type AccessTokenErrorResponse struct {
	// Error is an optional error string.
	ErrorType string `json:"error,omitempty"`
	// ErrorDescription is an optional error description.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI is an optional error URI.
	ErrorURI string `json:"error_uri,omitempty"`
}

// Error implements the error interface for AccessTokenErrorResponse.
func (e AccessTokenErrorResponse) Error() string {
	// Remove underscores of the .Error field
	// to make it more user-friendly.
	msg := e.ErrorDescription
	if msg == "" {
		switch e.ErrorType {
		case "invalid_request":
			msg = "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
		case "invalid_client":
			msg = "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."
		case "invalid_grant":
			msg = "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
		case "unauthorized_client":
			msg = "The authenticated client is not authorized to use this authorization grant type."
		case "unsupported_grant_type":
			msg = "The authorization grant type is not supported by the authorization server."
		case "invalid_scope":
			msg = "The requested scope is invalid, unknown, or malformed."
		}
	}

	return fmt.Sprintf("OAuth2 error (%s): %s", e.ErrorType, msg)
}

// ToQueryValues converts the AuthorizationErrorResponse to a url.Values to
// be easily converted to URL encoded query string.
func (e AccessTokenErrorResponse) ToQueryValues() url.Values {
	v := url.Values{}
	if e.ErrorType != "" {
		v.Set("error", e.ErrorType)
	}
	if e.ErrorDescription != "" {
		v.Set("error_description", e.ErrorDescription)
	}
	if e.ErrorURI != "" {
		v.Set("error_uri", e.ErrorURI)
	}
	return v
}
