package certs

import "errors"

var (
	ErrSecretDataMissing = errors.New("data missing from secret")
	ErrCARecreate        = errors.New("ca needs to be recreated but can't be")
)

func IsSecretDataMissing(err error) bool {
	return errors.Is(err, ErrSecretDataMissing)
}
