package resources

// Behaviors
type errNotFoundBehavior struct{}

func (e errNotFoundBehavior) IsErrNotFound() {}

func WithErrNotFound(err error) error {
	return struct {
		error
		errNotFoundBehavior
	}{
		err,
		errNotFoundBehavior{},
	}
}
