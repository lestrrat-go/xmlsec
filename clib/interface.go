package clib

import "errors"

const (
	DSigNs        = "http://www.w3.org/2000/09/xmldsig#"
	Prefix        = "ds"
	SignatureNode = "Signature"
)

type KeyDataType uint
const (
	KeyDataTypeUnknown   KeyDataType = 0x0000
	KeyDataTypeNone      KeyDataType = 0x0000
	KeyDataTypePublic    KeyDataType = 0x0001
	KeyDataTypePrivate   KeyDataType = 0x0002
	KeyDataTypeSymmetric KeyDataType = 0x0004
	KeyDataTypeSession   KeyDataType = 0x0008
	KeyDataTypePermanent KeyDataType = 0x0010
	KeyDataTypeTrusted   KeyDataType = 0x0100
	KeyDataTypeAny       KeyDataType = 0xFFFF
)

var (
	// ErrInvalidDSigCtx is returned when a dsig.Ctx is invalid
	ErrInvalidDSigCtx = errors.New("invalid dsig context")
	// ErrInvalidKey is returned when a crypto.Key is invalid
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidKeyType is returned when a the key type was invalid
	ErrInvalidKeyType = errors.New("invalid key type")
	// ErrInvalidKeysMngr is returned when a the key manager was invalid
	ErrInvalidKeysMngr = errors.New("invalid key manager")
)

// PtrSource defines the interface of things that wrap a C
// struct. Pointer method should return the underlying pointer
// in uintptr format.
type PtrSource interface {
	Pointer() uintptr
}
