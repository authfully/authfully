package authfully

import (
	"fmt"
	"net/http"
)

// Design Note:
// Handler of Authentication Endpoint should accept some sort
// of auth decoder to determine and handle if this is a:
//
// 1. Authentication submission; or
// 2. Authorization submission; or
// 3. None of the above (first arrival)

// AuthSubmissionType represents the type of submission. It should be
// either authorization or authentication.
type AuthSubmissionType int

const (
	// AuthenticationSubmission represents that the submission is an authentication (login)
	AuthenticationSubmission AuthSubmissionType = 1

	// AuthorizationSubmission represents that the submission is an authorization (scope authorization)
	AuthorizationSubmission AuthSubmissionType = 2
)

// String implements Stringer interface
func (t AuthSubmissionType) String() string {
	switch t {
	case AuthorizationSubmission:
		return "Authorization"
	case AuthenticationSubmission:
		return "Authentication"
	}
	return fmt.Sprintf("%v", int(t))
}

// GoString implements GoStringer for better debug
func (t AuthSubmissionType) GoString() string {
	return fmt.Sprintf("AuthSubmissionType(%s)", t)
}

// AuthSubmission represents either:
//  1. An authentication submission
//     (e.g. submission of login form or equivlant process result); or
//  2. An authorization submission
//     (e.g. submission of scope authorization form)
type AuthSubmission interface {

	// GetType gets the submission type.
	GetType() AuthSubmissionType

	// GetAuthorizationRequest gets the original authorization request
	GetAuthorizationRequest() *AuthorizationRequest

	// GetUser gets the user attempting the login, wether successful or
	// not. If the user cannot be identified or is not set, returns nil.
	GetUser() User

	// GetError gets, if any, error in the login process.
	GetError() error
}

// AuthSubmissionDecoder attempts, if the request is a form submission
// or equivlant, decode the submission attempt and check the submission result.
//
// For simplicity, "AuthSubmission" is both for authentication and authorization.
//
// It always return a AuthSubmission when this is a submission, even if the
// submission is invalid or the login has failed. The response writer need to
// know what kind of submission this is for error handling.
//
// Return the error at AuthSubmission.GetError() if there is an error.
type AuthSubmissionDecoder interface {
	Decode(r *http.Request) AuthSubmission
}

// AuthSubmissionDecoderFunc is a simplified implementation of AuthSubmissionDecoder.
type AuthSubmissionDecoderFunc func(r *http.Request) AuthSubmission

// Decode read and validate the authentication / authorization submisison from
// the request.
func (fn AuthSubmissionDecoderFunc) Decode(r *http.Request) AuthSubmission {
	return fn(r)
}
