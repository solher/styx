package resources

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
