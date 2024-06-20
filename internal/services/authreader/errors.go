package authreader

import "errors"

func IsUnauthorized(err error) bool {
	var unauthorizedError *unauthorizedError
	ok := errors.As(err, &unauthorizedError)

	return ok
}

type unauthorizedError struct {
	msg string
	err error
}

func (e *unauthorizedError) Error() string {
	return e.msg
}

func (e *unauthorizedError) Unwrap() error {
	return e.err
}
