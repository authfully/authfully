package authfully

import "context"

// WithEnvironment is a function that stores the environment in the context.
func WithEnvironment(ctx context.Context, env *Environment) {
	// Store the environment in the context
	ctx = context.WithValue(ctx, "environment", env)
}

// GetEnvironment retrieves the environment from the context.
func GetEnvironment(ctx context.Context) *Environment {
	env, ok := ctx.Value("environment").(*Environment)
	if !ok {
		return nil
	}
	return env
}

// WithClient is a function that stores the client in the context.
func WithClient(ctx context.Context, client Client) {
	// Store the client in the context
	ctx = context.WithValue(ctx, "client", client)
}

// GetClient is a function that retrieves the client from the context.
func GetClient(ctx context.Context) Client {
	client, ok := ctx.Value("client").(Client)
	if !ok {
		return nil
	}
	return client
}

// WithUser is a function that stores the user in the context.
func WithUser(ctx context.Context, user User) {
	// Store the user in the context
	ctx = context.WithValue(ctx, "user", user)
}

// GetUser is a function that retrieves the user from the context.
func GetUser(ctx context.Context) User {
	user, ok := ctx.Value("user").(User)
	if !ok {
		return nil
	}
	return user
}
