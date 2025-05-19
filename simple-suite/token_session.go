package authfullysimple

import (
	"fmt"
	"time"

	"github.com/authfully/authfully"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DefaultPendingTokenSession struct {
	// ID is the unique identifier for the token session.
	ID string `json:"id" gorm:"id,primaryKey"`

	// GrantType is the type of grant used for the token session.
	GrantType string `json:"grant_type"`

	// ClientID is the ID of the client making the request.
	ClientID string `json:"client_id"`

	// UserID is the ID of the user associated with the token session.
	UserID string `json:"user_id"`

	// Code is the authorization code received from the authorization server.
	Code string `json:"code" gorm:"code,index:idx_code,unique"`

	// CodeChallenge is the code challenge used for PKCE (Proof Key for Code Exchange).
	CodeChallenge string `json:"code_challenge"`

	// CodeChallengeMethod is the code challenge method used for PKCE (Proof Key for Code Exchange).
	CodeChallengeMethod string `json:"code_challenge_method"`

	// TokenType is the type of token requested.
	TokenType string `json:"token_type"`

	// Scope is the scope of the access request.
	Scope string `json:"scope"`
}

func (p DefaultPendingTokenSession) TableName() string {
	return "oauth2_pending_token_sessions"
}

func (p DefaultPendingTokenSession) GetID() string {
	return p.ID
}

func (p DefaultPendingTokenSession) GetGrantType() string {
	return p.GrantType
}

func (p DefaultPendingTokenSession) GetClientID() string {
	return p.ClientID
}

func (p DefaultPendingTokenSession) GetUserID() string {
	return p.UserID
}

func (p DefaultPendingTokenSession) GetCode() string {
	return p.Code
}

func (p DefaultPendingTokenSession) GetCodeChallenge() string {
	return p.CodeChallenge
}

func (p DefaultPendingTokenSession) GetCodeChallengeMethod() string {
	return p.CodeChallengeMethod
}

func (p DefaultPendingTokenSession) GetTokenType() string {
	return p.TokenType
}

func (p DefaultPendingTokenSession) GetScope() string {
	return p.Scope
}

type DefaultTokenSessionStore struct {
	// db is the database connection used to store the token session.
	db *gorm.DB

	// policy is the policy used to determine the expiration time of the token session.
	policy authfully.TokenSessionPolicy

	// tokenGenerator is the generator used to create new access or refresh tokens.
	tokenGenerator authfully.TokenGenerator
}

// DefaultTokenSession is an interface that represents a token session in the system.
// It is used to store the access token and other information
// after the token session is authorized by user.
type DefaultTokenSession struct {

	// ID is the unique identifier for the token session.
	ID string `json:"id"`

	// GrantType is the type of grant used for the token session.
	GrantType string `json:"grant_type"`

	// ClientID is the ID of the client making the request.
	ClientID string `json:"client_id"`

	// UserID is the ID of the user associated with the token session.
	UserID string `json:"user_id"`

	// TokenType is the type of token requested.
	TokenType string `json:"token_type"`

	// AccessToken is threq.TokenTypee access token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// RefreshToken is the refresh token issued by the authorization server.
	RefreshToken string `json:"refresh_token"`

	// AccessTokenExpiresAt is the expiration time of the access token.
	AccessTokenExpiresAt int64 `json:"access_token_expires_at"`

	// Scope is the scope of the access request.
	Scope string `json:"scope"`

	// Revoked is a boolean indicating whether the token session has been revoked.
	Revoked bool `json:"revoked"`
}

// GetID returns the ID of the token session.
func (t DefaultTokenSession) GetID() string {
	return t.ID
}

// GetGrantType returns the grant type of the token session.
func (t DefaultTokenSession) GetGrantType() string {
	return t.GrantType
}

// GetClientID returns the client ID of the token session.
func (t DefaultTokenSession) GetClientID() string {
	return t.ClientID
}

// GetUserID returns the user ID of the token session.
func (t DefaultTokenSession) GetUserID() string {
	return t.UserID
}

// GetTokenType returns the token type of the token session.
func (t DefaultTokenSession) GetTokenType() string {
	return t.TokenType
}

// GetAccessToken returns the access token of the token session.
func (t DefaultTokenSession) GetAccessToken() string {
	return t.AccessToken
}

// GetRefreshToken returns the refresh token of the token session.
func (t DefaultTokenSession) GetRefreshToken() string {
	return t.RefreshToken
}

// GetAccessTokenExpiresAt returns the expiration time of the access token.
func (t DefaultTokenSession) GetAccessTokenExpiresAt() int64 {
	return t.AccessTokenExpiresAt
}

// GetScope returns the scope of the access request.
func (t DefaultTokenSession) GetScope() string {
	return t.Scope
}

// IsRevoked returns whether the token session has been revoked.
func (t DefaultTokenSession) IsRevoked() bool {
	return t.Revoked
}

// NewTokenSessionStore creates a new DefaultTokenSessionStore with the given database connection.
func NewTokenSessionStore(
	db *gorm.DB,
	policy authfully.TokenSessionPolicy,
	tokenGenerator authfully.TokenGenerator,
) *DefaultTokenSessionStore {
	return &DefaultTokenSessionStore{
		db:             db,
		policy:         policy,
		tokenGenerator: tokenGenerator,
	}
}

// Create a new PendingTokenSession in the database.
func (s *DefaultTokenSessionStore) CreatePendingTokenSession(req *authfully.TokenSessionRequest, tokenType string) (authfully.PendingTokenSession, error) {
	var count int64 = 1
	var id string

	sess := &DefaultPendingTokenSession{
		GrantType:           req.GrantType,
		ClientID:            req.ClientID,
		UserID:              req.UserID,
		Code:                req.Code,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		TokenType:           tokenType,
		Scope:               req.Scope,
	}

	for count > 0 {
		// Generate a UUID for the client and check if it is unique
		id = uuid.New().String()
		q := s.db.Model(&DefaultPendingTokenSession{}).Where("id = ?", sess.ID)
		if q.Error != nil {
			return nil, fmt.Errorf("failed to check user ID uniqueness: %w", q.Error)
		}
		q.Count(&count)
	}
	sess.ID = id

	if err := s.db.Create(sess).Error; err != nil {
		return nil, fmt.Errorf("failed to create PendingTokenSession: %w", err)
	}
	return sess, nil
}

// GetPendingTokenSessionByID retrieves a pending token session by its ID from the database.
func (s *DefaultTokenSessionStore) GetPendingTokenSessionByID(id string) (authfully.PendingTokenSession, error) {
	var sess *DefaultPendingTokenSession
	if err := s.db.First(sess, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return sess, nil
}

// PromotePendingTokenSession creates a new token session from a pending token session.
func (s *DefaultTokenSessionStore) PromotePendingTokenSession(pendingTokenSession authfully.PendingTokenSession) (authfully.TokenSession, error) {
	sess := &DefaultTokenSession{
		ID:           pendingTokenSession.GetID(),
		GrantType:    pendingTokenSession.GetGrantType(),
		ClientID:     pendingTokenSession.GetClientID(),
		UserID:       pendingTokenSession.GetUserID(),
		TokenType:    pendingTokenSession.GetTokenType(),
		AccessToken:  s.tokenGenerator.Generate(),
		RefreshToken: s.tokenGenerator.Generate(),
		Scope:        pendingTokenSession.GetScope(),
	}
	sess.AccessTokenExpiresAt = s.policy.GetExpirationTime(sess, time.Now())

	if err := s.db.Create(sess).Error; err != nil {
		return nil, fmt.Errorf("failed to create token session from pending token session: %w", err)
	}
	return sess, nil
}

// GetTokenSessionByID retrieves a token session by its ID from the database.
func (s *DefaultTokenSessionStore) GetTokenSessionByID(id string) (authfully.TokenSession, error) {
	var sess *DefaultTokenSession
	if err := s.db.First(sess, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return sess, nil
}

// GetTokenSessionByCode retrieves a token session by its authorization code from the database.
func (s *DefaultTokenSessionStore) GetTokenSessionByCode(code string) (authfully.TokenSession, error) {
	var sess *DefaultTokenSession
	if err := s.db.First(sess, "code = ?", code).Error; err != nil {
		return nil, err
	}
	return sess, nil
}

// GetTokenSessionByAccessToken retrieves a token session by its access token from the database.
func (s *DefaultTokenSessionStore) GetTokenSessionByAccessToken(accessToken string) (authfully.TokenSession, error) {
	var sess *DefaultTokenSession
	if err := s.db.First(sess, "access_token = ?", accessToken).Error; err != nil {
		return nil, err
	}
	return sess, nil
}

// GetTokenSessionByRefreshToken retrieves a token session by its refresh token from the database.
func (s *DefaultTokenSessionStore) GetTokenSessionByRefreshToken(refreshToken string) (authfully.TokenSession, error) {
	var sess *DefaultTokenSession
	if err := s.db.First(sess, "refresh_token = ?", refreshToken).Error; err != nil {
		return nil, err
	}
	return sess, nil
}

// RevokeTokenSession revokes a token session by its ID in the database.
func (s *DefaultTokenSessionStore) RevokeTokenSession(id string) error {
	if err := s.db.Model(&DefaultTokenSession{}).Where("id = ?", id).Update("revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke token session: %w", err)
	}
	return nil
}

// AutoMigrate automatically migrates the database schema
// to match the DefaultTokenSession struct.
func (s *DefaultTokenSessionStore) AutoMigrate() error {
	if err := s.db.AutoMigrate(&DefaultTokenSession{}); err != nil {
		return fmt.Errorf("failed to migrate token session: %w", err)
	}
	if err := s.db.AutoMigrate(&DefaultPendingTokenSession{}); err != nil {
		return fmt.Errorf("failed to migrate pending token session: %w", err)
	}
	return nil
}
