package xmlsec

/*
#cgo pkg-config: xmlsec1
#include <stdlib.h>
#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>


*/
import "C"
import (
	"errors"

	"github.com/lestrrat/go-libxml2"
)

type KeyDataFormat int

const (
	KeyDataFormatUnknown  KeyDataFormat = C.xmlSecKeyDataFormatUnknown
	KeyDataFormatBinary                 = C.xmlSecKeyDataFormatBinary
	KeyDataFormatPem                    = C.xmlSecKeyDataFormatPem
	KeyDataFormatDer                    = C.xmlSecKeyDataFormatDer
	KeyDataFormatPkcs8Pem               = C.xmlSecKeyDataFormatPkcs8Pem
	KeyDataFormatPkcs8Der               = C.xmlSecKeyDataFormatPkcs8Der
	KeyDataFormatPkcs12                 = C.xmlSecKeyDataFormatPkcs12
	KeyDataFormatCertPem                = C.xmlSecKeyDataFormatCertPem
	KeyDataFormatCertDer                = C.xmlSecKeyDataFormatCertDer
)

func Init() error {
	if C.xmlSecInit() < C.int(0) {
		return errors.New("xmlsec initialization failed")
	}

	if C.xmlSecCryptoAppInit(nil) < C.int(0) {
		return errors.New("xmlsec crypt initialization failed")
	}

	return nil
}

func Shutdown() error {
	C.xmlSecCryptoShutdown()
	C.xmlSecCryptoAppShutdown()
	C.xmlSecShutdown()
	return nil
}

func xmlSecDSigCtxCreate() (*DSigCtx, error) {
	ctx := C.xmlSecDSigCtxCreate(nil)
	if ctx == nil {
		return nil, errors.New("failed to create DSigCtx")
	}
	return &DSigCtx{ptr: ctx}, nil
}

func xmlSecDSigCtxDestroy(ctx *DSigCtx) error {
	ptr := ctx.ptr
	if ptr == nil {
		return ErrInvalidDSigCtx
	}

	C.xmlSecDSigCtxDestroy(ptr)
	return nil
}

func xmlSecCryptoAppKeyLoad(file string, format KeyDataFormat) (*Key, error) {
	key := C.xmlSecCryptoAppKeyLoad(C.CString(file), (C.xmlSecKeyDataFormat)(format), nil, nil, nil)
	if key == nil {
		return nil, errors.New("failed to load key")
	}
	return &Key{ptr: key}, nil
}

func (ctx *DSigCtx) SetKey(key *Key) error {
	ptr := ctx.ptr
	if ptr == nil {
		return ErrInvalidDSigCtx
	}

	ptr.signKey = key.ptr
	return nil
}

func xmlSecDSigCtxSign(ctx *DSigCtx, n libxml2.Node) error {
	ptr := ctx.ptr
	if ptr == nil {
		return ErrInvalidDSigCtx
	}

	if C.xmlSecDSigCtxSign(ptr, (*C.xmlNode)(n.Pointer())) < C.int(0) {
		return errors.New("failed to sign node")
	}
	return nil
}
