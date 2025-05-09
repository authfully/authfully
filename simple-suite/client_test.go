package authfullysimple_test

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/authfully/authfully"
	authfullysimple "github.com/authfully/authfully/simple-suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestDefaultClientStore(t *testing.T) {

	// Debug environment setup
	logLevel := logger.Silent
	debugFlag := os.Getenv("DEBUG")
	dsn := ":memory:"
	if debugFlag != "" {
		logLevel = logger.Info
		dsn = t.Name() + ".sqlite3"

		if _, err := os.Stat(dsn); err == nil {
			// Remove the file if it exists
			err := os.Remove(dsn)
			if err != nil {
				log.Fatalf("Failed to remove file %s: %v", dsn, err)
			}
		}
	}
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logLevel,    // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      true,        // Don't include params in the SQL log
			Colorful:                  true,        // Disable color
		},
	)

	// Create a new in-memory SQLite database
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		panic("failed to connect database")
	}

	// Create a new ClientStore
	clientStore := authfullysimple.NewClientStore(db)

	// Checks if the ClientStore implements the authfully.ClientStore interface
	var _ authfully.ClientStore = clientStore

	// Migrate the schema
	err = clientStore.AutoMigrate()
	if err != nil {
		t.Fatalf("Failed to migrate schema: %v", err)
	}

	// Test creating a new client
	secretToUse := "my-secret"
	client := &authfullysimple.DefaultClient{
		ID:     "",
		Name:   "Test Client",
		UserID: "user-id",
	}
	client.SetSecret(secretToUse)
	err = clientStore.Create(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	if client.ID == "" {
		t.Fatalf("Client ID should not be empty after creation")
	}
	if want, have := client.ID, client.GetID(); want != have {
		t.Errorf("Expected client ID %s, got %s", want, have)
	}
	if client.SecretHash == "" {
		t.Errorf("Client secret hash should not be empty after creation")
	}
	if client.SecretHashMethod == "" {
		t.Errorf("Client secret hash method should not be empty after creation")
	}
	if client.SecretHashSalt == "" {
		t.Errorf("Client secret hash salt should not be empty after creation")
	}
	if client.CheckSecret(secretToUse) != nil {
		t.Errorf("Client secret check failed after creation")
	}

	// Test retrieving the client
	retrievedClient, err := clientStore.GetClientByID(client.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve client: %v", err)
	}
	if want, have := client.ID, retrievedClient.GetID(); want != have {
		t.Errorf("Expected client ID %s, got %s", want, have)
	}
	if want, have := client.Name, retrievedClient.GetName(); want != have {
		t.Errorf("Expected client name %s, got %s", want, have)
	}

	castedRetrivedClient, ok := retrievedClient.(*authfullysimple.DefaultClient)
	if !ok {
		t.Fatalf("Failed to cast retrieved client to authfullysimple.Client")
	}
	if want, have := client.SecretHash, castedRetrivedClient.SecretHash; want != have {
		t.Errorf("Expected client secret hash %s, got %s", want, have)
	}
	if want, have := client.SecretHashMethod, castedRetrivedClient.SecretHashMethod; want != have {
		t.Errorf("Expected client secret hash method %s, got %s", want, have)
	}
	if want, have := client.SecretHashSalt, castedRetrivedClient.SecretHashSalt; want != have {
		t.Errorf("Expected client secret hash salt %s, got %s", want, have)
	}
	if want, have := client.UserID, castedRetrivedClient.UserID; want != have {
		t.Errorf("Expected client user ID %s, got %s", want, have)
	}
	if want, have := client.RedirectURIs, castedRetrivedClient.RedirectURIs; len(want) != len(have) {
		t.Errorf("Expected client redirect URIs %v, got %v", want, have)
	} else {
		for i := range want {
			if want[i] != have[i] {
				t.Errorf("Expected client redirect URIs %v at pos %v, got %v", want, i, have)
				break
			}
		}
	}

	// Test updating the client
	client.Name = "Updated Client"
	err = clientStore.Update(client.ID, client)
	if err != nil {
		t.Fatalf("Failed to update client: %v", err)
	}
	retrievedClient, err = clientStore.GetClientByID(client.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated client: %v", err)
	}
	if retrievedClient.GetName() != "Updated Client" {
		t.Fatalf("Retrieved updated client does not match expected name")
	}

	// Test deleting the client
	err = clientStore.Delete(client.ID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	retrievedClient, err = clientStore.GetClientByID(client.ID)
	if err == nil {
		t.Fatalf("Expected error when retrieving deleted client, got none")
	}
	if retrievedClient != nil {
		t.Fatalf("Expected nil when retrieving deleted client, got %v", retrievedClient)
	}
}
