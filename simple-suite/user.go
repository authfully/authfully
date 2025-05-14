package authfullysimple

import (
	"fmt"

	"github.com/authfully/authfully"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DefaultUser is a struct that represents a user in the system.
// It implements authfully.DefaultUser interface.
type DefaultUser struct {
	ID                 string `json:"ID" gorm:"primaryKey,uniqueIndex"`
	Email              string `json:"Email" gorm:"uniqueIndex"`
	PasswordHash       string `json:"-"`
	PasswordHashSalt   string `json:"-"`
	PasswordHashMethod string `json:"-"`
}

// TableName returns the name of the table in the database.
// It is used by GORM to map the struct to the database table.
func (u *DefaultUser) TableName() string {
	return "oauth_users"
}

// CheckPassword checks if the given password matches the stored password hash.
func (u *DefaultUser) CheckPassword(password string) error {
	return CheckPassword(password, u.PasswordHash, u.PasswordHashSalt, u.PasswordHashMethod)
}

// SetPassword sets the password for the user by hashing it with a salt.
func (u *DefaultUser) SetPassword(password string) error {
	// Hardcode hash method to sha256
	hashMethod := "sha256"
	// Generate a new salt for the password hash
	salt := GenerateSalt()
	// Hash the password with the salt
	hash := HashPassword(password, salt, hashMethod)
	// Set the password hash and salt
	u.PasswordHash = hash
	u.PasswordHashSalt = salt
	u.PasswordHashMethod = hashMethod
	return nil
}

type DefaultUserStore struct {
	db *gorm.DB
}

// NewUserStore creates a new DefaultUserStore with the given database connection.
func NewUserStore(db *gorm.DB) *DefaultUserStore {
	return &DefaultUserStore{db: db}
}

// Create a new user in the database.
func (s *DefaultUserStore) Create(user *DefaultUser) error {
	var count int64 = 1
	var id string
	for count > 0 {
		// Generate a UUID for the client and check if it is unique
		id = uuid.New().String()
		q := s.db.Model(&DefaultClient{}).Where("id = ?", user.ID)
		if q.Error != nil {
			return fmt.Errorf("failed to check user ID uniqueness: %w", q.Error)
		}
		q.Count(&count)
	}
	user.ID = id

	if err := s.db.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// Update a user in the database.
func (s *DefaultUserStore) Update(id string, user *DefaultUser) error {
	if err := s.db.Model(&DefaultUser{}).Where("id = ?", id).Updates(user).Error; err != nil {
		return err
	}
	return nil
}

// Delete a user from the database.
func (s *DefaultUserStore) Delete(id string) error {
	if err := s.db.Delete(&DefaultUser{}, id).Error; err != nil {
		return err
	}
	return nil
}

// GetUserByID retrieves a user by their ID from the database.
func (s *DefaultUserStore) GetUserByID(id string) (authfully.User, error) {
	var user DefaultUser
	if err := s.db.First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByLoginName retrieves a user by their email address, user name, or any
func (s *DefaultUserStore) GetUserByLoginName(loginName string) (authfully.User, error) {
	var user DefaultUser
	if err := s.db.First(&user, "email = ?", loginName).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// AutoMigrate automatically migrates the database schema
// to match the DefaultUser struct.
func (cs *DefaultUserStore) AutoMigrate() error {
	// Migrate the schema
	if err := cs.db.AutoMigrate(&DefaultUser{}); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	return nil
}
