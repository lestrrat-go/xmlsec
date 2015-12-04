package clib

import "errors"

const (
	DSigNs        = "http://www.w3.org/2000/09/xmldsig#"
	Prefix        = "ds"
	SignatureNode = "Signature"
)

var (
	// ErrInvalidDSigCtx is returned when a dsig.Ctx is invalid
	ErrInvalidDSigCtx = errors.New("invalid dsig context")
	// ErrInvalidKey is returned when a crypto.Key is invalid
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidKeyType is returned when a the key type was invalid
	ErrInvalidKeyType = errors.New("invalid key type")
)

// PtrSource defines the interface of things that wrap a C
// struct. Pointer method should return the underlying pointer
// in uintptr format.
type PtrSource interface {
	Pointer() uintptr
}
