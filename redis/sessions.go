package redis

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"time"

	redigo "github.com/garyburd/redigo/redis"
	"github.com/pkg/errors"
	"github.com/solher/styx/helpers"
	"github.com/solher/styx/sessions"
)

type errNotFoundBehavior struct{}

func (err errNotFoundBehavior) IsErrNotFound() {}

type errValidationBehavior struct {
	field, reason string
}

func (err errValidationBehavior) IsErrValidation() {}
func (err errValidationBehavior) Field() string    { return err.field }
func (err errValidationBehavior) Reason() string   { return err.reason }

type errTokenUniqueness struct {
	helpers.ErrBehavior
	errValidationBehavior
}

func newErrTokenUniqueness(msg string) (err errTokenUniqueness) {
	defer func() {
		err.Msg = msg
		err.field = "token"
		err.reason = "unique"
	}()
	return errTokenUniqueness{}
}

type errSessionNotFound struct {
	helpers.ErrBehavior
	errNotFoundBehavior
}

func newErrSessionNotFound(msg string) (err errSessionNotFound) {
	defer func() { err.Msg = msg }()
	return errSessionNotFound{}
}

type sessionRepository struct {
	pool *redigo.Pool

	defaultTokenLength     int
	defaultSessionValidity time.Duration
}

// NewSessionRepository returns a new instance of a Redis backed session repository.
func NewSessionRepository(pool *redigo.Pool) sessions.Repository {
	return &sessionRepository{
		pool:                   pool,
		defaultTokenLength:     64,
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
// Each time we create a new session, we add the corresponding key in a ownerToken index to allow
// fast DeleteByOwnerToken operations.
// The problem is that we can't set an expiration on hash fields so we have to clear the index at each login.
// The logical effect is that after each login, we are sure that the index contains only active sessions.
func (r *sessionRepository) Create(ctx context.Context, session *sessions.Session) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	now := time.Now().UTC()
	session.Created = &now
	if session.ValidTo == nil {
		expirationTime := now.Add(r.defaultSessionValidity)
		session.ValidTo = &expirationTime
	}
	if session.Token == "" {
		session.Token = genToken(r.defaultTokenLength)
	}

	// We test the uniqueness of the token
	exists, err := redigo.Bool(conn.Do("EXISTS", sessionKey(session.Token)))
	if err != nil {
		return nil, errors.Wrap(err, "could not test the token uniqueness")
	}
	if exists {
		return nil, errors.Wrap(newErrTokenUniqueness("the session token must be unique"), "validation failed")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return nil, errors.Wrap(err, "new session marshalling failed")
	}

	// We set the new session and the associated index
	expiration := int(session.ValidTo.Sub(now).Seconds())
	sessionKey := sessionKey(session.Token)
	ownerSessionsKey := ownerSessionsKey(session.OwnerToken)
	_, err = conn.Do("SET", sessionKey, string(data), "EX", expiration, "NX")
	if err != nil {
		return nil, errors.Wrap(errors.New(""), "could not set a new session")
	}
	_, err = conn.Do("HSETNX", ownerSessionsKey, sessionKey, "")
	if err != nil {
		conn.Do("DEL", sessionKey)
		return nil, errors.Wrap(err, "could not set the session in the ownerToken index")
	}
	ttl, err := redigo.Int(conn.Do("TTL", ownerSessionsKey))
	if err != nil {
		return nil, errors.Wrap(err, "could not get the TTL of the ownerToken index")
	}
	if ttl < expiration {
		_, err := conn.Do("EXPIRE", ownerSessionsKey, expiration)
		if err != nil {
			conn.Do("DEL", sessionKey)
			conn.Do("HDEL", ownerSessionsKey, sessionKey)
			return nil, errors.Wrap(err, "could refresh the TTL of the ownerToken index")
		}
	}

	// We clear the associated index
	sessionKeys, err := redigo.Strings(conn.Do("HKEYS", ownerSessionsKey))
	if err != nil {
		return session, nil
	}
	for _, key := range sessionKeys {
		conn.Send("EXISTS", key)
	}
	ints, err := redigo.Ints(conn.Do(""))
	if err != nil {
		return session, nil
	}
	toDelete := []interface{}{}
	for i, exists := range ints {
		if exists == 0 {
			toDelete = append(toDelete, sessionKeys[i])
		}
	}
	if len(toDelete) > 0 {
		conn.Do("HDEL", append([]interface{}{ownerSessionsKey}, toDelete...)...)
	}

	return session, nil
}

// FindByToken finds a session by its token and returns it.
func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	return getSession(conn, sessionKey(token))
}

// DeleteByToken deletes a session by its token and returns it.
func (r *sessionRepository) DeleteByToken(ctx context.Context, token string) (*sessions.Session, error) {
	conn := r.pool.Get()
	defer conn.Close()

	session, err := getSession(conn, sessionKey(token))
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

	deleted := []sessions.Session{}
	ownerSessionsKey := ownerSessionsKey(ownerToken)
	sessionKeys, err := redigo.Values(conn.Do("HKEYS", ownerSessionsKey))
	if err != nil {
		return nil, errors.Wrap(err, "could not get the ownerToken index")
	}
	if sessionKeys == nil || len(sessionKeys) == 0 {
		return deleted, nil
	}
	vals, err := redigo.ByteSlices(conn.Do("MGET", sessionKeys...))
	if err != nil {
		return nil, errors.Wrap(err, "could not get the sessions by ownerToken")
	}
	for _, val := range vals {
		session := sessions.Session{}
		if err := json.Unmarshal(val, &session); err != nil {
			return nil, errors.Wrap(err, "found session unmarshalling failed")
		}
		deleted = append(deleted, session)
	}
	conn.Do("DEL", append([]interface{}{ownerSessionsKey}, sessionKeys...)...)

	return deleted, nil
}

func getSession(conn redigo.Conn, key string) (*sessions.Session, error) {
	val, err := redigo.Bytes(conn.Do("GET", key))
	if err != nil {
		return nil, errors.Wrap(newErrSessionNotFound(err.Error()), "could not get a session by key")
	}
	session := &sessions.Session{}
	if err := json.Unmarshal(val, session); err != nil {
		return nil, errors.Wrap(err, "found session unmarshalling failed")
	}
	return session, nil
}

func sessionKey(token string) string {
	return "session:" + token
}

func ownerSessionsKey(ownerToken string) string {
	return "ownerSessions:" + ownerToken
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
