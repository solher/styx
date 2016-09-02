package redis

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"time"

	redigo "github.com/garyburd/redigo/redis"
	"github.com/pkg/errors"
	"github.com/solher/styx/sessions"
)

type sessionRepository struct {
	pool *redigo.Pool

	defaultTokenLength     int
	defaultSessionValidity time.Duration
}

// NewSessionRepository returns a new instance of a Redis backed session repository.
func NewSessionRepository(pool *redigo.Pool) sessions.Repository {
	return &sessionRepository{
		pool:                   pool,
		defaultTokenLength:     32,
		defaultSessionValidity: 24 * time.Hour,
	}
}

// SetDefaultTokenLength sets the default length of generated session tokens.
func (r *sessionRepository) SetDefaultTokenLength(tokenLength int) *sessionRepository {
	r.defaultTokenLength = tokenLength
	return r
}

// SetDefaultSessionValidity sets the default duration of new sessions validity.
func (r *sessionRepository) SetDefaultSessionValidity(sessionValidity time.Duration) *sessionRepository {
	r.defaultSessionValidity = sessionValidity
	return r
}

// Create creates a new session and returns it.
func (r *sessionRepository) Create(ctx context.Context, session *sessions.Session) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	now := time.Now().UTC()
	session.Created = &now
	if session.Token == "" {
		session.Token = genToken(r.defaultTokenLength)
	}
	if session.ValidTo == nil {
		expirationTime := now.Add(r.defaultSessionValidity)
		session.ValidTo = &expirationTime
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, errors.Wrap(err, "new session marshalling failed")
	}

	sessionKey := sessionKey(session.Token)
	conn.Send("HSETNX", sessionKey, "session", string(data))
	_, err = conn.Do("HSETNX", sessionKey, "ownerToken", session.OwnerToken)
	if err != nil {
		return nil, errors.Wrap(err, "could not set a new session")
	}
	_, err = conn.Do("EXPIREAT", sessionKey, session.ValidTo.Unix())
	if err != nil {
		conn.Do("DEL", sessionKey)
		return nil, errors.Wrap(err, "could not set the expiration on the new session")
	}

	return session, nil
}

// FindByToken finds a session by its token and returns it.
func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	reply, err := redigo.Bytes(conn.Do("HGET", "session", sessionKey(token)))
	if err != nil {
		return nil, sessions.ErrNotFound
	}
	var session *sessions.Session
	if err := json.Unmarshal(reply, session); err != nil {
		return nil, errors.Wrap(err, "found session unmarshalling failed")
	}

	return session, nil
}

// DeleteByToken deletes a session by its token and returns it.
func (r *sessionRepository) DeleteByToken(ctx context.Context, token string) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	session, err := r.FindByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	_, err = conn.Do("DEL", sessionKey(token))
	if err != nil {
		return nil, errors.Wrap(err, "session deletion failed")
	}

	return session, nil
}

// DeleteByOwnerToken deletes all the sessions marked with the given owner token.
// Useful to implement delete cascades on user deletions.
// The implementation is very slow so should probably be runned asynchronously in background.
// TODO: Find another cleaner way.
func (r *sessionRepository) DeleteByOwnerToken(ctx context.Context, ownerToken string) ([]sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	cursor := 0
	first := true
	for cursor != 0 || first {
		values, err := redigo.Values(conn.Do("SCAN", cursor, "MATCH", sessionKey("*")))
		if err != nil {
			return nil, errors.Wrap(err, "session scan failed")
		}
		cursor = values[0].(int)
		keys := values[1].([]string)
		for _, key := range keys {
			token, err := redigo.String(conn.Do("HGET", key, "ownerToken"))
			if err != nil {
				continue
			}
			if token == ownerToken {
				conn.Do("DEL", key)
			}
		}
		if first {
			first = false
		}
	}

	return nil, nil
}

func sessionKey(token string) string {
	return "session:" + token
}

func genToken(strSize int) string {
	dictionary := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	var bytes = make([]byte, strSize)
	rand.Read(bytes)

	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}

	return string(bytes)
}
