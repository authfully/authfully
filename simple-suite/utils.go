package authfullysimple

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultBcryptCost    = bcrypt.DefaultCost
	defaultArgon2Time    = 1
	defaultArgon2Memory  = 64 * 1024
	defaultArgon2Threads = 4
	defaultArgon2KeyLen  = 32
	defaultArgon2SaltLen = 16
)

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

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
	case "argon2id":
		salt, err := generateSalt(defaultArgon2SaltLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate salt: %v", err)
		}

		hash := argon2.IDKey([]byte(password), salt, defaultArgon2Time, defaultArgon2Memory, defaultArgon2Threads, defaultArgon2KeyLen)
		settings := url.Values{
			"v": []string{"19"},
			"m": []string{strconv.Itoa(defaultArgon2Memory)},
			"t": []string{strconv.Itoa(defaultArgon2Time)},
			"p": []string{strconv.Itoa(defaultArgon2Threads)},
			"l": []string{strconv.Itoa(defaultArgon2KeyLen)},
		}
		encodeSettings := base64.StdEncoding.EncodeToString([]byte(settings.Encode()))
		encodedHash := base64.URLEncoding.EncodeToString(hash)
		encodedSalt := base64.URLEncoding.EncodeToString(salt)
		encodedStr := fmt.Sprintf(
			"%s$%s$%s",
			encodeSettings,
			encodedSalt,
			encodedHash,
		)
		return encodedStr, nil
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
	case "argon2id":
		parts := strings.Split(hash, "$")
		if len(parts) != 3 {
			return fmt.Errorf("internal error: invalid hash format")
		}

		log.Printf("parts: %v", parts)

		// Decode the settings for argon2id from the hash string
		settingStr, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return fmt.Errorf("internal error: failed to decode hash settings: %v", err)
		}
		settings, err := url.ParseQuery(string(settingStr))
		if err != nil {
			return fmt.Errorf("internal error: failed to parse hash settings: %v", err)
		}
		m, err := strconv.Atoi(settings.Get("m"))
		if err != nil {
			return fmt.Errorf("internal error: failed to parse memory size: %v", err)
		}
		t, err := strconv.Atoi(settings.Get("t"))
		if err != nil {
			return fmt.Errorf("internal error: failed to parse time cost: %v", err)
		}
		p, err := strconv.Atoi(settings.Get("p"))
		if err != nil {
			return fmt.Errorf("internal error: failed to parse parallelism: %v", err)
		}
		l, err := strconv.Atoi(settings.Get("l"))
		if err != nil {
			return fmt.Errorf("internal error: failed to parse key length: %v", err)
		}

		// Decode the salt and hash from the hash string
		salt, err := base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return fmt.Errorf("internal error: failed to decode salt: %v", err)
		}
		hashBytes, err := base64.URLEncoding.DecodeString(parts[2])
		if err != nil {
			return fmt.Errorf("internal error: failed to decode hash: %v", err)
		}

		// Hash the password using argon2id with the same parameters
		computedHash := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(p), uint32(l))

		// Compare the computed hash with the stored hash
		if len(computedHash) != len(hashBytes) {
			return fmt.Errorf("password does not match: %v", err)
		}
		for i := range computedHash {
			if computedHash[i] != hashBytes[i] {
				return fmt.Errorf("password does not match: %v", err)
			}
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
