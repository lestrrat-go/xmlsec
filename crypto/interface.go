package crypto

import (
	"github.com/lestrrat-go/xmlsec/clib"
)

type KeyDataType clib.KeyDataType
const (
	KeyDataTypeUnknown   = clib.KeyDataTypeUnknown
	KeyDataTypeNone      = clib.KeyDataTypeNone
	KeyDataTypePublic    = clib.KeyDataTypePublic
	KeyDataTypePrivate   = clib.KeyDataTypePrivate
	KeyDataTypeSymmetric = clib.KeyDataTypeSymmetric
	KeyDataTypeSession   = clib.KeyDataTypeSession
	KeyDataTypePermanent = clib.KeyDataTypePermanent
	KeyDataTypeTrusted   = clib.KeyDataTypeTrusted
	KeyDataTypeAny       = clib.KeyDataTypeAny
)

type KeyDataFormat clib.KeyDataFormat
const (
	KeyDataFormatUnknown  = clib.KeyDataFormatUnknown
	KeyDataFormatBinary   = clib.KeyDataFormatBinary
	KeyDataFormatPem      = clib.KeyDataFormatPem
	KeyDataFormatDer      = clib.KeyDataFormatDer
	KeyDataFormatPkcs8Pem = clib.KeyDataFormatPkcs8Pem
	KeyDataFormatPkcs8Der = clib.KeyDataFormatPkcs8Der
	KeyDataFormatPkcs12   = clib.KeyDataFormatPkcs12
	KeyDataFormatCertPem  = clib.KeyDataFormatCertPem
	KeyDataFormatCertDer  = clib.KeyDataFormatCertDer
)

type Key struct {
	ptr uintptr // *C.xmlSecKey
}

type KeyManager struct {
	ptr uintptr
}

