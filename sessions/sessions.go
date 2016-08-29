package sessions

import (
	"encoding/json"
	"errors"
	"time"
)

// Session associates a unique token, an abstract/custom user payload
// and a list of policies for a certain amount of time.
type Session struct {
	// The creation timestamp.
	Created *time.Time `json:"created,omitempty"`
	// The validity time limit of the session.
	ValidTo *time.Time `json:"validTo,omitempty"`
	// The authentication token identifying the session.
	Token string `json:"token,omitempty"`
	// An optional token identifying a user in the auth system.
	OwnerToken string `json:"ownerToken,omitempty"`
	// The end user agent.
	Agent string `json:"agent,omitempty"`
	// The end user IP adress.
	IP string `json:"ip,omitempty"`
	// The list of the policy names associated with the session.
	Policies []string `json:"policies,omitempty"`
	// A client custom payload. It is not checked or verified.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ErrNotFound is used when a session could not be found.
var ErrNotFound = errors.New("session not found")

// Repository provides access to a session store.
type Repository interface {
	FindByToken(token string) (*Session, error)
	Create(session *Session) (*Session, error)
	DeleteByToken(token string) (*Session, error)
	DeleteByOwnerToken(ownerToken string) ([]Session, error)
}
