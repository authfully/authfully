package authfullysimple

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultBcryptCost = bcrypt.DefaultCost
)

// GenerateClientSecret generates a random secret for the client.
func GenerateClientSecret(clientId string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(clientId), defaultBcryptCost)
	return base64.URLEncoding.EncodeToString(hash), err
}

// HashPassword hashes the password using the specified algo.
func HashPassword(password, algo string) (string, error) {
	// Use SHA256 hashing algorithm
	// and return the base64 encoded hash
	switch strings.ToLower(algo) {
	case "bcrypt":
		hash, err := bcrypt.GenerateFromPassword([]byte(password), defaultBcryptCost)
		return base64.URLEncoding.EncodeToString(hash), err
	default:
		// This should not happen. Immediately panic if it does.
		panic(fmt.Sprintf("unsupported hash algo: %s", algo))
	}
}

// CheckPassword checks if the password matches the hash using the specified algo.
func CheckPassword(password, hash, algo string) error {
	// Use SHA256 hashing algorithm
	// and compare the hash with the stored password hash
	switch algo {
	case "bcrypt":
		bcryptHash, err := base64.URLEncoding.DecodeString(hash)
		if err != nil {
			return fmt.Errorf("failed to decode bcrypt hash: %v", err)
		}
		err = bcrypt.CompareHashAndPassword(bcryptHash, []byte(password))
		if err != nil {
			return fmt.Errorf("password does not match: %v", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported hash algo: %s", algo)
	}
}

// ParseAddress parses the port string and returns a formatted address.
// If the port string is empty, it uses the default port.
// It returns an error if the port number is invalid.
// The address is formatted as ":<port>".
func ParseAddress(portStr, defaultPort string) (string, error) {
	if portStr == "" {
		portStr = defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("port number out of range: %d", port)
	}
	return ":" + strconv.Itoa(port), nil
}
