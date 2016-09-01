package redis

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
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

	conn.Send("MULTI")
	_, err = conn.Do("SET", sessionKey(session.Token), string(data), "NX")
	if err != nil {
		conn.Do("DISCARD")
		return nil, errors.Wrap(err, "could not set a new session")
	}
	conn.Send("EXPIREAT", sessionKey(session.Token), session.ValidTo.Unix())
	conn.Send("SET", ownerTokenIndexKey(session.OwnerToken, session.Token), "NX")
	_, err = conn.Do("EXEC")
	if err != nil {
		return nil, errors.Wrap(err, "could not set an ownerTokenIndex")
	}

	return session, nil
}

// FindByToken finds a session by its token and returns it.
func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	reply, err := redigo.Bytes(conn.Do("GET", sessionKey(token)))
	if err != nil {
		return nil, sessions.ErrNotFound
	}
	var session *sessions.Session
	if err := json.Unmarshal(reply, session); err != nil {
		return nil, errors.Wrap(err, "found session unmarshalling failed")
	}

	return nil, nil
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
func (r *sessionRepository) DeleteByOwnerToken(ctx context.Context, ownerToken string) ([]sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	cursor := 0
	first := true
	for cursor != 0 || first {
		values, err := redigo.Values(conn.Do("SCAN", cursor, "MATCH", ownerTokenIndexKey(ownerToken, "*")))
		if err != nil {
			return nil, errors.Wrap(err, "session scan failed")
		}
		cursor = values[0].(int)
		keys := values[1].([]string)
		for _, key := range keys {
			_, err = conn.Do("DEL", tokenFromIndex(key))
			if err != nil {
				return nil, errors.Wrap(err, "session deletion by owner token failed")
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

func ownerTokenIndexKey(ownerToken, token string) string {
	return fmt.Sprintf("ownerTokenIndex:%s-%s", ownerToken, token)
}

func tokenFromIndex(ownerTokenIndexKey string) string {
	return strings.Split(ownerTokenIndexKey, "-")[1]
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
