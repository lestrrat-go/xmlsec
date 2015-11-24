package xmlsec

/*
#cgo pkg-config: xmlsec1
#include <xmlsec/xmldsig.h>
*/
import "C"
import "errors"

var (
	ErrInvalidDSigCtx = errors.New("invalid dsig context")
)

type DSigCtx struct {
	ptr *C.xmlSecDSigCtx
}

type Key struct {
	ptr *C.xmlSecKey
}
