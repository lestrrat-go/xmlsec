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

const (
	SignatureNode = "Signature"
	DSigNs        = "http://www.w3.org/2000/09/xmldsig#"
)

type DSigCtx struct {
	ptr *C.xmlSecDSigCtx
}

type Key struct {
	ptr *C.xmlSecKey
}
