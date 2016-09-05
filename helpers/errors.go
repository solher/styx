package helpers

type ErrBehavior struct {
	Msg string
}

func (err ErrBehavior) Error() string {
	return err.Msg
}
