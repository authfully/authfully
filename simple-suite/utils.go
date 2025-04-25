package authfullysimple

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

func generateSalt() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to generate salt: %v", err))
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func hashPassword(password, salt, method string) string {
	// Use SHA256 hashing algorithm
	// and return the base64 encoded hash
	switch strings.ToLower(method) {
	case "sha256":
		hasher := sha256.New()
		hasher.Write([]byte(password))
		hasher.Write([]byte(salt))
		return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	default:
		// This should not happen. Immediately panic if it does.
		panic(fmt.Sprintf("unsupported hash method: %s", method))
	}
}

func checkPassword(password, hash, salt, method string) error {
	// Use SHA256 hashing algorithm
	// and compare the hash with the stored password hash
	var passwordHash string
	switch strings.ToLower(method) {
	case "sha256":
		hasher := sha256.New()
		hasher.Write([]byte(password))
		hasher.Write([]byte(salt))
		passwordHash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	default:
		return fmt.Errorf("unsupported hash method: %s", method)
	}

	if passwordHash != hash {
		return fmt.Errorf("password does not match")
	}
	return nil
}
