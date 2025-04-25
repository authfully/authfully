package authfully

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
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
	<title>Login</title>
</head>
<body>
	<h1>Login</h1>
	<form method="POST" action="{{ .Action }}">
		<p>Login</p>
		<input type="text" name="email" placeholder="Email" value="{{ .Email }}" required>
		<input type="password" name="password" placeholder="Password" required>
		<button type="submit">Login</button>
	</form>
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
	{{- if .ErrorType }}
		<h1>{{ .ErrorType }}</h1>
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
	Logger                      slog.Logger
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
	Decode(r *http.Request) (*AuthorizationRequest, error)
}

// AuthorizationRequestDecoderFunc is a function type that implements
// the AuthorizationRequestDecoder interface. It takes an HTTP request
// and returns an AuthorizationRequest and an error.
type AuthorizationRequestDecoderFunc func(r *http.Request) (*AuthorizationRequest, error)

// Decode decodes the authorization request from the given HTTP request.
func (f AuthorizationRequestDecoderFunc) Decode(r *http.Request) (*AuthorizationRequest, error) {
	return f(r)
}

// DefaultAuthorizationRequestDecoder is a default implementation of
// AuthorizationRequestDecoder that decodes the authorization request
// from the URL query parameters.
func DefaultAuthorizationRequestDecoder(r *http.Request) (*AuthorizationRequest, error) {
	// Decode the authorization request from the URL query parameters
	// and return an AuthorizationRequest.
	q := r.URL.Query()
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

	// TODO: improve validataion logics

	return req, nil
}

// AuthorizationEndpointHandler handles all requests to the authorization
// endpoint
type AuthorizationEndpointHandler struct {
	AuthenticationPageTemplate     *template.Template
	ScopeAuthorizationPageTemplate *template.Template
	ErrorPageTemplate              *template.Template
}

// NewAuthorizationEndpointHandler creates a new AuthorizationEndpointHandler
// with the necessary templates for rendering the authentication and
// authorization pages.
//
// It panics if any of the templates fail to parse.
func NewAuthorizationEndpointHandler() *AuthorizationEndpointHandler {
	var err error
	ScopeAuthorizationPageTemplate, err := template.New("scope_authorization").Parse(ScopeAuthorizationPageHTML)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse scope authorization page template: %v", err))
	}
	AuthenticationPageTemplate, err := template.New("authentication").Parse(AuthenticationPageHTML)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse authentication page template: %v", err))
	}
	ErrorPageTemplate, err := template.New("error").Parse(ErrorPageHTML)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse error page template: %v", err))
	}

	return &AuthorizationEndpointHandler{
		AuthenticationPageTemplate:     AuthenticationPageTemplate,
		ScopeAuthorizationPageTemplate: ScopeAuthorizationPageTemplate,
		ErrorPageTemplate:              ErrorPageTemplate,
	}
}

func (h AuthorizationEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	env := GetEnvironment(r.Context())
	if env == nil {
		panic("Environment not found")
	}
	if env.AuthSubmissionDecoder == nil {
		panic("Environment.AuthSubmissionDecoder not found")
	}

	sub := env.AuthSubmissionDecoder.Decode(r)
	if sub == nil {
		// First arriving at the endpoint
		req, err := env.AuthorizationRequestDecoder.Decode(r)
		if err != nil {
			// Report and log error
			env.Logger.Error("Failed to decode authorization request", slog.String("error", err.Error()))

			// Basic error handling
			err := AuthErrorResponse{
				ErrorType:        "invalid_request",
				ErrorDescription: "Failed to decode authorization request",
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			h.ErrorPageTemplate.Execute(w, struct {
				Title            string
				ErrorDescription string
				RedirectURI      string
			}{
				Title:            err.ErrorType,
				ErrorDescription: err.ErrorDescription,
				RedirectURI:      req.RedirectURI + "?" + err.ToQueryValues().Encode(),
			})
			return
		}

		// Get client information
		c, err := GetAndValidateClientFromAuthorizationRequest(r.Context(), req)
		if err != nil {
			// Report and log error
			env.Logger.Error("Failed to get client from authorization request", slog.String("error", err.Error()))

			// Basic error handling
			err := AuthErrorResponse{
				ErrorType:        "invalid_request",
				ErrorDescription: "Failed to get client from authorization request",
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			h.ErrorPageTemplate.Execute(w, struct {
				Title            string
				ErrorDescription string
				RedirectURI      string
			}{
				Title:            err.ErrorType,
				ErrorDescription: err.ErrorDescription,
				RedirectURI:      req.RedirectURI + "?" + err.ToQueryValues().Encode(),
			})
			return
		}

		h.ScopeAuthorizationPageTemplate.Execute(w, struct {
			Action string
			Client Client
		}{
			Action: env.AuthEndpoint,
			Client: c,
		})
		return
	}
	switch sub.GetType() {
	case AuthenticationSubmission:
		// Check form submission result, then the pending token session,
		// If everything is legit, show the authorization form or equivlant UI.
		c, err := env.ClientStore.GetClientByID(sub.GetAuthorizationRequest().ClientID)
		if err != nil {
			// Report and log error
			env.Logger.Error("Failed to get client from authorization request", slog.String("error", err.Error()))

			// Basic error handling
			err := AuthErrorResponse{
				ErrorType:        "invalid_request",
				ErrorDescription: "Failed to get client from authorization request",
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			h.ErrorPageTemplate.Execute(w, struct {
				Title            string
				ErrorDescription string
				RedirectURI      string
			}{
				Title:            err.ErrorType,
				ErrorDescription: err.ErrorDescription,
				RedirectURI:      sub.GetAuthorizationRequest().RedirectURI + "?" + err.ToQueryValues().Encode(),
			})
			return
		}

		// Access token scope is a list of space-delimited case-sensitive strings.
		// https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
		//
		// TODO: add a way to map the scope to a list of user readable
		//       explainations of the machine-readable scope.
		scopes := strings.Split(sub.GetAuthorizationRequest().Scope, " ")

		// Render the scope authorization page
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		h.ScopeAuthorizationPageTemplate.Execute(w, struct {
			Action string
			Client Client
			Scopes []string
		}{
			Action: env.AuthEndpoint,
			Client: c,
			Scopes: scopes,
		})
		return
	case AuthorizationSubmission:
		// Check form submission result, then the pending token session,
		// If everything is legit, redirect back to client with proper
		// response / error.
		resp, err := HandleAuthorizationSubmission(r.Context(), sub, w)
		if err != nil {
			// Report and log error
			env.Logger.Error("Failed to handle authorization submission", slog.String("error", err.Error()))

			// Basic error handling
			err := AuthErrorResponse{
				ErrorType:        "invalid_request",
				ErrorDescription: "Failed to handle authorization submission",
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			h.ErrorPageTemplate.Execute(w, struct {
				Title            string
				ErrorDescription string
				RedirectURI      string
			}{
				Title:            err.ErrorType,
				ErrorDescription: err.ErrorDescription,
				RedirectURI:      sub.GetAuthorizationRequest().RedirectURI + "?" + err.ToQueryValues().Encode(),
			})
			return
		}
		if resp == nil {
			// Report and log error
			env.Logger.Error("Failed to handle authorization submission", slog.String("error", "nil response"))

			// Basic error handling
			err := AuthErrorResponse{
				ErrorType:        "invalid_request",
				ErrorDescription: "Failed to handle authorization submission",
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			h.ErrorPageTemplate.Execute(w, struct {
				Title            string
				ErrorDescription string
				RedirectURI      string
			}{
				Title:            err.ErrorType,
				ErrorDescription: err.ErrorDescription,
				RedirectURI:      sub.GetAuthorizationRequest().RedirectURI + "?" + err.ToQueryValues().Encode(),
			})
			return
		}

		// Redirect to the client with the authorization response
		q := resp.ToQueryValues()
		if resp.AccessTokenResponse != nil || resp.AccessTokenErrorResponse != nil {
			// For implicit flow, the access token is returned in the URL fragment.
			w.Header().Set("Location",
				sub.GetAuthorizationRequest().RedirectURI+"#"+q.Encode(),
			)
			return
		}

		w.Header().Set("Location",
			sub.GetAuthorizationRequest().RedirectURI+"?"+q.Encode(),
		)
		return
	default:
		// Unknown submission type
		// Report and log error
		env.Logger.Error("Unknown submission type", slog.String("type", sub.GetType().String()))

		// Basic error handling
		err := AuthErrorResponse{
			ErrorType:        "invalid_request",
			ErrorDescription: "Unknown submission type",
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		h.ErrorPageTemplate.Execute(w, struct {
			Title            string
			ErrorDescription string
			RedirectURI      string
		}{
			Title:            err.ErrorType,
			ErrorDescription: err.ErrorDescription,
			RedirectURI:      sub.GetAuthorizationRequest().RedirectURI + "?" + err.ToQueryValues().Encode(),
		})
		return
	}

}

/*
// HandleAuthenticationSubmission generates the proper authentication response
// from the given request, client and user.
func HandleAuthenticationSubmission(
	ctx context.Context,
	sub AuthSubmission,
	w http.ResponseWriter,
) (*AuthResponse, error) {
	env := GetEnvironment(ctx)
	if env == nil {
		panic("Environment is not set in the context")
	}
	client := GetClient(ctx)
	if client == nil {
		return nil, fmt.Errorf("Client is not set in the context")
	}
	user := GetUser(ctx)
	if user == nil {
		return nil, fmt.Errorf("User is not set in the context")
	}

	return nil, fmt.Errorf("HandleAuthenticationSubmission not implemented")
}
*/

// HandleAuthorizationRequest generates the proper authorization response
// from the given request, client and user.
//
// Client and user are supposed to be already authenticated and validated.
func HandleAuthorizationSubmission(
	ctx context.Context,
	sub AuthSubmission,
	w http.ResponseWriter,
) (*AuthResponse, error) {

	env := GetEnvironment(ctx)
	if env == nil {
		panic("Environment is not set in the context")
	}
	client := GetClient(ctx)
	if client == nil {
		return nil, fmt.Errorf("Client is not set in the context")
	}
	user := GetUser(ctx)
	if user == nil {
		return nil, fmt.Errorf("User is not set in the context")
	}
	req := sub.GetAuthorizationRequest()

	switch req.ResponseType {
	case "code":
		// Handle authorization code flow
		// Generate authorization code
		code, err := env.RandomGenerator.Generate(32)
		if err != nil {
			return nil, err
		}

		ps, err := env.TokenSessionStore.CreatePendingTokenSession(&TokenSessionRequest{
			GrantType:           "authorization_code",
			ClientID:            req.ClientID,
			Code:                code,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			Scope:               req.Scope,
		})
		if err != nil {
			return nil, err
		}

		// Generate response for authorization code flow
		resp := &AuthResponse{
			ResponseType: req.ResponseType,
			Code:         ps.GetCode(),
			State:        req.State,
		}
		return resp, nil

	case "token":
		ps, err := env.TokenSessionStore.CreatePendingTokenSession(&TokenSessionRequest{
			GrantType: "implicit",
			ClientID:  req.ClientID,
		})
		if err != nil {
			return nil, err
		}

		sess, err := env.TokenSessionStore.PromotePendingTokenSession(ps)
		if err != nil {
			return nil, err
		}

		// Generate response for implicit flow
		resp := &AuthResponse{
			ResponseType: req.ResponseType,
			AccessTokenResponse: &AccessTokenResponse{
				AccessToken: sess.GetAccessToken(),
				TokenType:   sess.GetTokenType(),
				ExpiresIn:   CalculateExpiresIn(sess.GetAccessTokenExpiry()),
				Scope:       sess.GetScope(),
				State:       req.State,
			},
		}
		return resp, nil
	}

	return nil, fmt.Errorf("unsupported response type: %s", req.ResponseType)
}

/*
// AuthorizationEndpointResponseWriter is an interface that extends
// http.ResponseWriter to provide additional functionality for
// handling authorization responses in the OAuth 2.0 flow.
//
// It allows for the retrieval of the authorization response context,
// which can be used to accumulate information about the authorization
// request, user, and client during the authorization process.
type AuthorizationEndpointResponseWriter interface {
	http.ResponseWriter

	// GetAuthResponseContext get the authorization context
	// to furhter accumulate to or render output with.
	GetAuthResponseContext() AuthResponseContext
}

// AuthResponseContext represents a context in the
// OAuth 2.0 authentication / authorization process.
//
//  1. On first arrival at the authorization endpoint, a pending session
//     is created with basic client information.
//  2. After the user is authenticated, the user will be asked to
//     authorize the application to access their data.
//  3. After the user authorized the application, the pending session
//     is promoted to a token session and the user is redirected back
//     to the application with the authorization code or access token.
//
// The underlying implementation of the pending session should be
// a pointer. So getting the AuthResponseContext and modifying it
// allows other middleware / http.Handler to access the same context
// information.
type AuthResponseContext interface {
	SetAuthorizationRequest(*AuthorizationRequest)

	GetAuthorizationRequest() *AuthorizationRequest

	SetAuthResponse(*AuthResponse)

	GetAuthResponse() *AuthResponse

	SetClient(Client)

	GetClient() Client

	SetUser(User)

	GetUser() User

	SetPendingTokenSession(PendingTokenSession)

	GetPendingTokenSession() PendingTokenSession

	SetError(error)

	GetError() error
}
*/
