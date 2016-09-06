package sessions

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

type errValidationBehavior struct {
	field, reason string
}

func (e errValidationBehavior) IsErrValidation() {}
func (e errValidationBehavior) Field() string    { return e.field }
func (e errValidationBehavior) Reason() string   { return e.reason }

// WithErrValidation adds a errValidationBehavior to the given error.
func WithErrValidation(err error, field, reason string) error {
	return struct {
		error
		errValidationBehavior
	}{
		err,
		errValidationBehavior{
			field:  field,
			reason: reason,
		},
	}
}
