package authfullysimple

import (
	"fmt"
	"slices"
	"strings"
)

// Client is a struct that represents an OAuth 2.0 client.
// It implements authfully.Client interface.
type Client struct {
	ID               string `json:"ID"`
	SecretHash       string `json:"-"`
	SecretHashSalt   string `json:"-"`
	SecretHashMethod string `json:"-"`

	// UserID stores the owner of the client.
	UserID string `json:"UserID"`

	// RedirectURIs is a list of valid redirect URIs for the client.
	RedirectURIs []string `json:"RedirectURIs"`

	// Scopes is a list of valid scopes for the client.
	Scopes []string `json:"Scopes"`
}

// CheckSecret checks the given secret string against the client
// to see if it is valid.
func (c *Client) CheckSecret(secret string) error {
	return checkPassword(secret, c.SecretHash, c.SecretHashSalt, c.SecretHashMethod)
}

// SetSecret sets the secret for the client by hashing it with a salt.
func (c *Client) SetSecret(secret string) error {
	// Hardcode hash method to sha256
	hashMethod := "sha256"
	// Generate a new salt for the secret hash
	salt := generateSalt()
	// Hash the secret with the salt
	hash := hashPassword(secret, salt, hashMethod)
	// Set the secret hash and salt
	c.SecretHash = hash
	c.SecretHashSalt = salt
	c.SecretHashMethod = hashMethod
	return nil
}

// CheckRedirectURI checks if the redirect URI matches the supposed redirect URI.
func (c *Client) CheckRedirectURI(redirectURI string) error {
	// Remove query parameters from the redirect URI
	// and trim any leading or trailing whitespace
	bareRedirectURI := strings.Split(redirectURI, "?")[0]
	bareRedirectURI = strings.TrimSpace(bareRedirectURI)
	if slices.Contains(c.RedirectURIs, bareRedirectURI) {
		return nil
	}
	return fmt.Errorf("invalid redirect URI")
}
