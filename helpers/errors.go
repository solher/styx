package helpers

type BasicError struct {
	msg string
}

func (err BasicError) Error() string {
	return err.msg
}

func NewBasicError(msg string) BasicError { return BasicError{msg: msg} }
