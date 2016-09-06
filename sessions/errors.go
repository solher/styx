package sessions

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

type errValidation interface {
	error
	IsErrValidation()
	Field() string
	Reason() string
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

// IsErrValidation returns true if err implements errValidation.
func IsErrValidation(err error) (string, string, bool) {
	e, ok := err.(errValidation)
	if !ok {
		return "", "", false
	}
	return e.Field(), e.Reason(), true
}
