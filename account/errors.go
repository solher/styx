package account

// Types
type (
	errNotFound interface {
		error
		IsErrNotFound()
	}
	errValidation interface {
		error
		IsErrValidation()
		Field() string
		Reason() string
	}
)

// Behaviors
type errNotFoundBehavior struct{}

func (e errNotFoundBehavior) IsErrNotFound() {}

func withErrNotFound(err error) error {
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

func withErrValidation(err error, field, reason string) error {
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
