package xmlsec

/*
#cgo pkg-config: xmlsec1
#include <xmlsec/crypto.h>
#include <xmlsec/xmldsig.h>

static inline xmlSecTransformId MY_Sha1Id() {
	return xmlSecTransformSha1Id;
}

static inline xmlSecTransformId MY_RsaSha1Id() {
	return xmlSecTransformRsaSha1Id;
}

*/
import "C"
import (
	"errors"

	"github.com/lestrrat/go-libxml2"
)

var (
	ErrInvalidDSigCtx = errors.New("invalid dsig context")
	ErrInvalidKeyType = errors.New("invalid key type")
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

type TransformID struct {
	ptr C.xmlSecTransformId
}

var (
	ExclC14N  = TransformID{ptr: C.xmlSecTransformExclC14NGetKlass()}
	Enveloped = TransformID{ptr: C.xmlSecTransformEnvelopedGetKlass()}
	Sha1      = TransformID{ptr: C.MY_Sha1Id()}
	RsaSha1   = TransformID{ptr: C.MY_RsaSha1Id()}
)

type Signature struct {
	refnode    libxml2.Node
	signmethod TransformID
	signnode   libxml2.Node
}
