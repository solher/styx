package account

import "github.com/solher/styx/sessions"

type (
	errValidation interface {
		error
		IsAccountErrValidation()
		Field() string
		Reason() string
	}
)

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

func isErrValidation(err error) (string, string, bool) {
	if e, ok := err.(errValidation); ok {
		return e.Field(), e.Reason(), true
	} else if field, reason, ok := sessions.IsErrValidation(err); ok {
		return field, reason, true
	}
	return "", "", false
}
