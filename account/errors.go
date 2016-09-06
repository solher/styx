package account

type errNotFound interface {
	error
	IsErrNotFound()
}

func isErrNotFound(err error) bool {
	_, ok := err.(errNotFound)
	return ok
}

type errValidation interface {
	error
	IsErrValidation()
	ValidationField() string
	ValidationReason() string
}

type errValidationBehavior struct {
	field, reason string
}

func (e errValidationBehavior) IsErrValidation()         {}
func (e errValidationBehavior) ValidationField() string  { return e.field }
func (e errValidationBehavior) ValidationReason() string { return e.reason }

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

func isErrValidation(err error) (string, string, bool) {
	if e, ok := err.(errValidation); ok {
		return e.ValidationField(), e.ValidationReason(), true
	}
	return "", "", false
}
