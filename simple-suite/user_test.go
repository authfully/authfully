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

func TestDefaultUserStore(t *testing.T) {
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

	// Create a new database
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		panic("failed to connect database")
	}

	// Create a new user store
	userStore := authfullysimple.NewUserStore(db)

	// Checks if the UserStore implements the authfully.UserStore interface
	var _ authfully.UserStore = userStore

	// Migrate the schema
	err = userStore.AutoMigrate()
	if err != nil {
		t.Fatalf("Failed to migrate schema: %v", err)
	}

	// Create a new user
	passwordToUse := "password"
	user := &authfullysimple.DefaultUser{
		ID:    "123",
		Email: "test@test.com",
	}
	user.SetPassword(passwordToUse)
	err = userStore.Create(user)
	if err != nil {
		t.Errorf("Failed to create user: %v", err)
	}

	// Retrieve the user by ID
	retrievedUser, err := userStore.GetUserByID(user.ID)
	if err != nil {
		t.Errorf("Failed to retrieve user: %v", err)
	}
	retrievedCastedUser, ok := retrievedUser.(*authfullysimple.DefaultUser)
	if !ok {
		t.Fatalf("Failed to cast retrieved user to DefaultUser")
	}
	if want, have := retrievedCastedUser.ID, user.ID; want != have {
		t.Errorf("Expected user ID %s, got %s", want, have)
	}
	if want, have := retrievedCastedUser.Email, user.Email; want != have {
		t.Errorf("Expected user email %s, got %s", want, have)
	}
	if retrievedCastedUser.PasswordHash == "" {
		t.Errorf("Expected user password hash to be set, got empty string")
	}
	if want, have := retrievedCastedUser.PasswordHash, user.PasswordHash; want != have {
		t.Errorf("Expected user password hash %s, got %s", want, have)
	}
	if retrievedCastedUser.PasswordHashAlgo == "" {
		t.Errorf("Expected user password hash method to be set, got empty string")
	}
	if want, have := user.PasswordHashAlgo, retrievedCastedUser.PasswordHashAlgo; want != have {
		t.Errorf("Expected user password hash method %s, got %s", want, have)
	}
	if err := retrievedUser.CheckPassword(passwordToUse); err != nil {
		t.Errorf("Failed to check password: %v", err)
	}
}
