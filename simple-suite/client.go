package authfullysimple

import (
	"fmt"
	"slices"
	"strings"

	"github.com/authfully/authfully"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DefaultClient is a struct that represents an OAuth 2.0 client.
// It implements authfully.DefaultClient interface.
type DefaultClient struct {
	gorm.Model
	ID             string `json:"ID" gorm:"primaryKey,uniqueIndex"`
	Name           string `json:"Name"`
	SecretHash     string `json:"-"`
	SecretHashAlgo string `json:"-"`

	// UserID stores the owner of the client.
	UserID string `json:"UserID"`

	// RedirectURIs is a list of valid redirect URIs for the client.
	RedirectURIs []string `json:"RedirectURIs" gorm:"serializer:json"`

	// Scopes is a list of valid scopes for the client.
	Scopes []string `json:"Scopes" gorm:"serializer:json"`
}

// TableName returns the name of the table in the database.
// This is used by GORM to map the struct to the table.
func (c *DefaultClient) TableName() string {
	return "oauth_clients"
}

// GetID returns the ID of the client.
// Implements the authfully.Client interface.
func (c *DefaultClient) GetID() string {
	return c.ID
}

// GetName returns the human-readable name of the client.
// Implements the authfully.Client interface.
func (c *DefaultClient) GetName() string {
	return c.Name
}

// CheckSecret checks the given secret string against the client
// to see if it is valid.
// Implements the authfully.Client interface.
func (c *DefaultClient) CheckSecret(secret string) error {
	return CheckPassword(secret, c.SecretHash, c.SecretHashAlgo)
}

// SetSecret sets the secret for the client by hashing it with a salt.
func (c *DefaultClient) SetSecret(secret string) error {
	// Hardcode hash method to sha256
	algo := "bcrypt"

	// Hash the secret with the salt
	hash, err := HashPassword(secret, algo)
	if err != nil {
		return err
	}

	// Set the secret hash and salt
	c.SecretHash = hash
	c.SecretHashAlgo = algo
	return nil
}

// CheckRedirectURI checks if the redirect URI matches the supposed redirect URI.
// Implements the authfully.Client interface.
func (c *DefaultClient) CheckRedirectURI(redirectURI string) error {
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
// Implements the authfully.Client interface.
func (c *DefaultClient) CheckScope(scope string) error {
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

// DefaultClientStore is an implementation of authfully.DefaultClientStore
type DefaultClientStore struct {
	db *gorm.DB
}

// NewClientStore creates a new ClientStore instance
func NewClientStore(db *gorm.DB) *DefaultClientStore {
	return &DefaultClientStore{
		db: db,
	}
}

// Create creates a new client in the database
func (cs *DefaultClientStore) Create(client *DefaultClient) error {
	var count int64 = 1
	var id string
	for count > 0 {
		// Generate a UUID for the client and check if it is unique
		id = uuid.New().String()
		q := cs.db.Model(&DefaultClient{}).Where("id = ?", client.ID)
		if q.Error != nil {
			return fmt.Errorf("failed to check client ID uniqueness: %w", q.Error)
		}
		q.Count(&count)
	}
	client.ID = id

	if err := cs.db.Create(client).Error; err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	return nil
}

// Update updates an existing client in the database
func (cs *DefaultClientStore) Update(id string, client *DefaultClient) error {
	if err := cs.db.Model(&DefaultClient{}).Where("id = ?", id).Updates(client).Error; err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}
	return nil
}

// Delete deletes a client from the database
func (cs *DefaultClientStore) Delete(id string) error {
	if err := cs.db.Where("id = ?", id).Delete(&DefaultClient{}).Error; err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// Close closes the database connection
// Implements the authfully.ClientStore interface.
func (cs *DefaultClientStore) GetClientByID(id string) (authfully.Client, error) {
	var client DefaultClient
	if err := cs.db.Where("id = ?", id).First(&client).Error; err != nil {
		return nil, fmt.Errorf("failed to get client by ID: %w", err)
	}
	return &client, nil
}

// AutoMigrate automatically migrates the database schema
// to match the DefaultClient struct.
func (cs *DefaultClientStore) AutoMigrate() error {
	// Migrate the schema
	if err := cs.db.AutoMigrate(&DefaultClient{}); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	return nil
}
