package authfully

import "context"

type contextKey int

const (
	contextKeyEnvironment contextKey = iota
	contextKeyClient
	contextKeyUser
	contextKeyAuthorizationRequest
)

// WithEnvironment is a function that stores the environment in the context.
func WithEnvironment(ctx context.Context, env *Environment) context.Context {
	// Store the environment in the context
	return context.WithValue(ctx, contextKeyEnvironment, env)
}

// GetEnvironment retrieves the environment from the context.
func GetEnvironment(ctx context.Context) *Environment {
	env, ok := ctx.Value(contextKeyEnvironment).(*Environment)
	if !ok {
		return nil
	}
	return env
}

// WithClient is a function that stores the client in the context.
func WithClient(ctx context.Context, client Client) context.Context {
	// Store the client in the context
	return context.WithValue(ctx, contextKeyClient, client)
}

// GetClient is a function that retrieves the client from the context.
func GetClient(ctx context.Context) Client {
	client, ok := ctx.Value(contextKeyClient).(Client)
	if !ok {
		return nil
	}
	return client
}

// WithUser is a function that stores the user in the context.
func WithUser(ctx context.Context, user User) context.Context {
	// Store the user in the context
	return context.WithValue(ctx, contextKeyUser, user)
}

// GetUser is a function that retrieves the user from the context.
func GetUser(ctx context.Context) User {
	user, ok := ctx.Value(contextKeyUser).(User)
	if !ok {
		return nil
	}
	return user
}

// WithAuthorizationRequest is a function that stores the authorization request
// in the context.
func WithAuthorizationRequest(ctx context.Context, req *AuthorizationRequest) context.Context {
	return context.WithValue(ctx, contextKeyAuthorizationRequest, req)
}

// GetAuthorizationRequest get authorization request from context
func GetAuthorizationRequest(ctx context.Context) *AuthorizationRequest {
	req, ok := ctx.Value(contextKeyAuthorizationRequest).(*AuthorizationRequest)
	if !ok {
		return nil
	}
	return req
}
