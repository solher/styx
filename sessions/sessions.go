package sessions

import (
	"context"
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
	Payload []byte `json:"payload,omitempty"`
}

// Repository provides access to a session store.
type Repository interface {
	Create(ctx context.Context, session *Session) (*Session, error)
	FindByToken(ctx context.Context, token string) (*Session, error)
	DeleteByToken(ctx context.Context, token string) (*Session, error)
	DeleteByOwnerToken(ctx context.Context, ownerToken string) ([]Session, error)
}
