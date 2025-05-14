package authfullysimple

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// GenerateSalt generates a random salt for the password hash.
func GenerateSalt() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to generate salt: %v", err))
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// GenerateClientSecret generates a random secret for the client.
func GenerateClientSecret(clientId, salt string) string {
	method := "sha256"
	return HashPassword(clientId, salt, method) + ":" + method + "!" + salt // FIXME: better way to do this
}

func HashPassword(password, salt, method string) string {
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

func CheckPassword(password, hash, salt, method string) error {
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
