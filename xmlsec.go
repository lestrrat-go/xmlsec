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
import "errors"

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
