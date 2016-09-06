package policies

type errNotFound interface {
	error
	IsErrNotFound()
}

type errNotFoundBehavior struct{}

func (e errNotFoundBehavior) IsErrNotFound() {}

// WithErrNotFound adds a errNotFoundBehavior to the given error.
func WithErrNotFound(err error) error {
	return struct {
		error
		errNotFoundBehavior
	}{
		err,
		errNotFoundBehavior{},
	}
}

// IsErrNotFound returns true if err implements errNotFound.
func IsErrNotFound(err error) bool {
	_, ok := err.(errNotFound)
	return ok
}
