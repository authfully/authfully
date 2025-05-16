package authfully

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// AuthenticationPageHTML holds a generic HTML template
	// for the authentication form.
	AuthenticationPageHTML = `
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>{{- if .Title }}{{ .Title }}{{- else }}Login{{- end}}</title>
	<style>
		.user-authentication {
			display: block;
			max-width: 400px;
			width: calc(100% - 2rem);
			margin: 0 auto;
		}
		.user-authentication__form {
			display: flex;
			flex-direction: column;
			gap: 1rem 0;
		}
		.user-authentication__form__input {
			padding: 0.5rem;
			border: 1px solid #ccc;
			border-radius: 4px;
			font-size: 1.2rem;
		}
		.user-authentication__form__button {
			padding: 0.5rem;
			border: 1px solid #ccc;
			border-radius: 4px;
			font-size: 1.2rem;
			cursor: pointer;
		}
		.authentication__form__warning {
			background-color: #f8d7da;
			color: #721c24;
			padding: 1rem;
			border: 1px solid #f5c6cb;
			border-radius: 4px;
			margin-bottom: 1rem;
		}
		.authentication__form__warning h2 {
			margin: 0;
			font-size: 1.2rem;
			font-weight: bold;
		}
		.authentication__form__warning p {
			margin: 0;
			font-size: 1rem;
		}
	</style>
</head>
<body>
	<main class="user-authentication">
		<h1>{{- if .Title }}{{ .Title }}{{- else }}Login{{- end}}</h1>
		{{- if .Warning }}
			<div class="authentication__form__warning">
				{{- if .Warning.Title }}
					<h2>{{ .Warning.Title }}</h2>
				{{- end }}
				<p>{{ .Warning.Description }}</p>
			</div>
		{{- end }}
		<form method="POST" action="{{ .Action }}" class="user-authentication__form">
			<input
				class="user-authentication__form__input"
				type="text"
				name="email"
				placeholder="Email"
				value="{{- if .Form }}{{ .Form.Get "email" }}{{- else  }}{{- end }}"
				required
			>
			<input
				class="user-authentication__form__input"
				type="password"
				name="password"
				placeholder="Password"
				required
			>
			<button
				class="user-authentication__form__button"
				type="submit"
			>Login</button>
		</form>
	</main>
</body>
</html>
`

	// ScopeAuthorizationPageHTML holds a generic HTML template
	// for the scope authorization form.
	ScopeAuthorizationPageHTML = `
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>Authorization</title>
</head>
<body>
	<h1>Authorization</h1>
	<form method="POST" action="{{ .Action }}">
		<p>Client: {{ .Client.GetName }}</p>
		<ul>
			{{- range .Scopes }}
			 	<li>{{ . }}</li>
			{{- end }}
		</ul>
		<button type="submit">Authorize</button>
	</form>
</body>
</html>
`
	// ErrorPageHTML holds a generic HTML template
	// for the error page.
	ErrorPageHTML = `
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>Error</title>
</head>
<body>
	{{- if .Title }}
		<h1>{{ .Title }}</h1>
	{{- else }}
		<h1>Error</h1>
	{{- end }}
	{{- if .ErrorDescription }}
		<p>{{ .ErrorDescription }}</p>
	{{- end }}
	<p>
		<a class="btn" href="{{ .RedirectURI }}">Back to application</a>
	</p>
</body>
</html>
`
)

/**
 * Code Authorization Workflow:
 *
 * 1. User initiates authorization request in application
 * 2. Application redirects user to authorization server's authorization endpoint
 * 3. Authorization endpoint shows a login form or some other UI / interaction to
 *    authenticate the user. This can be a multi-step process. A pending session
 *    should be created when the user arrived at the authorization endpoint with
 *    a correct response_type, client_id and redirect_uri.
 * 4. After successfully authenticated, a user interaction step is required for the
 *    user to authorize the application to access their data (given the requested
 *    scopes). Basic user information, after login, should be stored in cookies or
 *    (jwt) or sessions.
 * 5. After both authentication and authorization, the authorization server
 *    either promote the pending session or remove / invalidate it. And the it should
 *    redirect the user back to the application with appropriate response
 *    (authorization code or access token or error).
 */

type RandomGenerator interface {
	// Generate generates a random string of the specified length.
	Generate(length int) (string, error)
}

// DefaultRandomGenerator is a default implementation of RandomGenerator
type DefaultRandomGenerator struct {
	Letters []rune
}

// NewDefaultRandomGenerator creates a new default RandomGenerator implementation
func NewRandomGenerator() RandomGenerator {
	return &DefaultRandomGenerator{
		Letters: []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
	}
}

// Generate generates a random string of the specified length.
func (g *DefaultRandomGenerator) Generate(length int) (string, error) {
	b := make([]rune, length)
	for i := range b {
		b[i] = g.Letters[rand.Intn(len(g.Letters))]
	}
	return string(b), nil
}

// Environment is a struct that holds the necessary components
// for handling OAuth 2.0 authorization requests and responses.
type Environment struct {
	AuthEndpoint                string
	TokenEndpoint               string
	UserStore                   UserStore
	ClientStore                 ClientStore
	TokenSessionStore           TokenSessionStore
	RandomGenerator             RandomGenerator
	AuthorizationRequestDecoder AuthorizationRequestDecoder
	AuthSubmissionDecoder       AuthSubmissionDecoder
	AuthSessionHandler          AuthSessionHandler
	Logger                      *slog.Logger
}

// CalculateExpiresIn calculates the remaining time until the token expires.
func CalculateExpiresIn(expires int64) int64 {
	now := time.Now().Unix()
	return expires - now
}

// GetAndValidateClientFromAuthorizationRequest validates the client from the authorization request.
func GetAndValidateClientFromAuthorizationRequest(
	ctx context.Context,
	req *AuthorizationRequest,
) (Client, error) {
	env := GetEnvironment(ctx)
	if env == nil {
		panic("Environment is not set in the context")
	}

	c, err := env.ClientStore.GetClientByID(req.ClientID)
	if err != nil {
		return nil, err
	}
	// Check if the client accept the requested scopes
	if err := c.CheckScope(req.Scope); err != nil {
		return c, err
	}
	// Check if the client accept the requested redirect URI
	if err := c.CheckRedirectURI(req.RedirectURI); err != nil {
		return c, err
	}

	return c, nil
}

// AuthorizationRequestDecoder is an interface that defines a method
// for decoding an authorization request from an HTTP request.
type AuthorizationRequestDecoder interface {
	// Decode decodes the authorization request from the given HTTP request.
	// It returns an AuthorizationRequest if the request is valid, or nil
	// if the request is invalid.
	//
	// If the request is invalid or misformed, it should return an error
	// with the error message and the error description.
	Decode(q url.Values) (*AuthorizationRequest, error)
}

// AuthorizationRequestDecoderFunc is a function type that implements
// the AuthorizationRequestDecoder interface. It takes an HTTP request
// and returns an AuthorizationRequest and an error.
type AuthorizationRequestDecoderFunc func(q url.Values) (*AuthorizationRequest, error)

// Decode decodes the authorization request from the given HTTP request.
func (f AuthorizationRequestDecoderFunc) Decode(q url.Values) (*AuthorizationRequest, error) {
	return f(q)
}

// DefaultAuthorizationRequestDecoder is a default implementation of
// AuthorizationRequestDecoder that decodes the authorization request
// from the URL query parameters.
func DefaultAuthorizationRequestDecoder(q url.Values) (*AuthorizationRequest, error) {
	// Decode the authorization request from the URL query parameters
	// and return an AuthorizationRequest.
	req := &AuthorizationRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		Scope:               q.Get("scope"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}

	// validate the request
	if req.ResponseType == "" {
		return nil, fmt.Errorf("missing response_type")
	} else if req.ResponseType != "code" && req.ResponseType != "token" {
		return nil, fmt.Errorf("invalid response_type: %s", req.ResponseType)
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}
	if req.RedirectURI == "" {
		return nil, fmt.Errorf("missing redirect_uri")
	}
	if req.Scope == "" {
		return nil, fmt.Errorf("missing scope")
	}

	// Validate that the redirect uri is a valid URI
	parsedURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect_uri: %w", err)
	}

	// Check the scheme (must be http or https)
	if parsedURI.Scheme != "http" && parsedURI.Scheme != "https" {
		return nil, fmt.Errorf("invalid redirect_uri: scheme must be http or https")
	}

	// Check that the host is not empty
	if parsedURI.Host == "" {
		return nil, fmt.Errorf("invalid redirect_uri: missing host")
	}

	// Validate the format of req.Scope
	// to spec, it need to be "space-delimited case sensitive strings"
	//
	//   scope       = scope-token *( SP scope-token )
	//   scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
	//
	// ref: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
	scopes := strings.Fields(req.Scope)
	if len(scopes) == 0 && req.Scope != "" { // Handles case where scope might be just spaces
		return nil, fmt.Errorf("invalid scope: must be space-delimited strings")
	}
	for _, s := range scopes {
		if !isValidScopeToken(s) {
			return nil, fmt.Errorf("invalid scope token: %s", s)
		}
	}

	// TODO: improve validataion logics for PKCE's code challenge and
	// challenge method

	return req, nil
}

// isValidScopeToken checks if a single scope token is valid according to RFC6749.
// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
func isValidScopeToken(token string) bool {
	if len(token) == 0 {
		return false
	}
	for _, r := range token {
		if r == 0x20 || r == 0x22 || r == 0x5C { // SP, DQUOTE, BACKSLASH are not allowed
			return false
		}
		if r < 0x21 || r > 0x7E { // Must be in VCHAR range
			return false
		}
	}
	return true
}

// SubmissionError is for commonly used submission status response.
type SubmissionError int

const (
	// SubmissionOK indicates that the handler handled a submission
	// with an OK status.
	SubmissionOK SubmissionError = iota

	// SubmissionInvalid is a generic "submission invalid" error
	// meant only for development use. Please use AuthErrorResponse
	// or other error implementation for a proper error response.
	SubmissionInvalid
)

func (e SubmissionError) Error() string {
	switch e {
	case SubmissionOK:
		return "ok"
	case SubmissionInvalid:
		return "submission invalid"
	}
	return fmt.Sprintf("unknown submission error: %d", int(e))
}

// UserInterfacePageFields is a generic struct that holds the warning
// message and the form data for displaying in the user interface.
type UserInterfacePageFields struct {
	Title                string
	ButtonText           string
	Action               string
	Warning              *UserInterfaceWarning
	AuthorizationRequest *AuthorizationRequest
	Form                 url.Values
	Extra                map[string]any
}

// ErrorPageFields is a struct that holds the fields for
// displaying an error page.
type ErrorPageFields struct {
	Title            string
	ButtonText       string
	ErrorDescription string
	RedirectURI      string
}

// AuthSession is a struct that holds the information about
type AuthSession struct {
	// ID is the ID of the session.
	ID string `json:"id"`

	// AuthorizationRequest is the original authorization request.
	AuthorizationRequest *AuthorizationRequest `json:"authorization_request,omitempty"`

	// UserID is the ID of the user who has logged in.
	// If a user has not logged in, this field is empty.
	UserID string `json:"user_id,omitempty"`

	// ExpiresAt is the time when the session expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthSessionHandler is an interface that defines methods for
// getting and setting the authentication session in the HTTP request.
type AuthSessionHandler interface {
	// GetSession gets the session from the request.
	GetSession(r *http.Request) (*AuthSession, error)

	// SetSession sets the session in the request.
	SetSession(w http.ResponseWriter, r *http.Request, session *AuthSession) error

	// DeleteSession deletes the session from the request.
	DeleteSession(w http.ResponseWriter, r *http.Request) error
}
