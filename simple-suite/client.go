package authfullysimple

import (
	"fmt"
	"slices"
	"strings"

	"github.com/authfully/authfully"
	"gorm.io/gorm"
)

// Client is a struct that represents an OAuth 2.0 client.
// It implements authfully.Client interface.
type Client struct {
	gorm.Model
	Name             string `json:"Name"`
	ID               string `json:"ID"`
	SecretHash       string `json:"-"`
	SecretHashSalt   string `json:"-"`
	SecretHashMethod string `json:"-"`

	// UserID stores the owner of the client.
	UserID string `json:"UserID"`

	// RedirectURIs is a list of valid redirect URIs for the client.
	RedirectURIs []string `json:"RedirectURIs" gorm:"serializer:json"`

	// Scopes is a list of valid scopes for the client.
	Scopes []string `json:"Scopes" gorm:"serializer:json"`
}

// GetID returns the ID of the client.
func (c *Client) GetID() string {
	return c.ID
}

// GetName returns the human-readable name of the client.
func (c *Client) GetName() string {
	return c.Name
}

// CheckSecret checks the given secret string against the client
// to see if it is valid.
func (c *Client) CheckSecret(secret string) error {
	return CheckPassword(secret, c.SecretHash, c.SecretHashSalt, c.SecretHashMethod)
}

// SetSecret sets the secret for the client by hashing it with a salt.
func (c *Client) SetSecret(secret string) error {
	// Hardcode hash method to sha256
	hashMethod := "sha256"
	// Generate a new salt for the secret hash
	salt := generateSalt()
	// Hash the secret with the salt
	hash := HashPassword(secret, salt, hashMethod)
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

// CheckScope checks if all the requested scopes are valid for the client.
func (c *Client) CheckScope(scope string) error {
	// Split the scope string into a slice of scopes
	scopes := strings.Split(scope, " ")
	// Check if all requested scopes are valid for the client
	invalidScopes := make([]string, 0)
	for _, s := range scopes {
		if !slices.Contains(c.Scopes, s) {
			invalidScopes = append(invalidScopes, s)
		}
	}
	if len(invalidScopes) > 0 {
		return fmt.Errorf("invalid scopes: %s", strings.Join(invalidScopes, ", "))
	}
	return nil
}

// ClientStore is an implementation of authfully.ClientStore
type ClientStore struct {
	db *gorm.DB
}

// NewClientStore creates a new ClientStore instance
func NewClientStore(db *gorm.DB) *ClientStore {
	return &ClientStore{
		db: db,
	}
}

// Create creates a new client in the database
func (cs *ClientStore) Create(client *Client) error {
	if err := cs.db.Create(client).Error; err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	return nil
}

// Update updates an existing client in the database
func (cs *ClientStore) Update(id string, client *Client) error {
	if err := cs.db.Model(&Client{}).Where("id = ?", id).Updates(client).Error; err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}
	return nil
}

// Delete deletes a client from the database
func (cs *ClientStore) Delete(id string) error {
	if err := cs.db.Delete(&Client{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// Close closes the database connection
func (cs *ClientStore) GetClientByID(id string) (authfully.Client, error) {
	var client Client
	if err := cs.db.Where("id = ?", id).First(&client).Error; err != nil {
		return nil, fmt.Errorf("failed to get client by ID: %w", err)
	}
	return &client, nil
}

func (cs *ClientStore) AutoMigrate() error {
	// Migrate the schema
	if err := cs.db.AutoMigrate(&Client{}); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	return nil
}
