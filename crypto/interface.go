package crypto

import (
	"github.com/lestrrat/go-xmlsec/clib"
)

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
