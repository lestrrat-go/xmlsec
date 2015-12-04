package dsig

import (
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-xmlsec/clib"
)

var (
	ExclC14N  = clib.ExclC14N
	Enveloped = clib.Enveloped
	Sha1      = clib.Sha1
	RsaSha1   = clib.RsaSha1
)

type Ctx struct {
	ptr uintptr // *C.xmlSecDSigCtx
}

type Signature struct {
	keyinfo    types.Node
	refnode    types.Node
	signmethod clib.TransformID
	signnode   types.Node
}
