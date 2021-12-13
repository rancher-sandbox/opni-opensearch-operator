package pki

import "errors"

var (
	ErrDecodeCA     = errors.New("unable to decode CA PEM")
	ErrDecodeCAKey  = errors.New("unabled to decode CA key PEM")
	ErrCertExpiring = errors.New("cert expiring within 10 days")
)
