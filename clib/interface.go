package clib

import "errors"

const (
	DSigNs        = "http://www.w3.org/2000/09/xmldsig#"
	Prefix        = "ds"
	SignatureNode = "Signature"
)

var (
	ErrInvalidDSigCtx = errors.New("invalid dsig context")
	ErrInvalidKey     = errors.New("invalid key")
	ErrInvalidKeyType = errors.New("invalid key type")
)

type PtrSource interface {
	Pointer() uintptr
}
