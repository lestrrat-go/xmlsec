package dsig

import (
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-xmlsec/clib"
)

type TransformID clib.TransformID
var (
	ExclC14N  = TransformID(clib.ExclC14N)
	Enveloped = TransformID(clib.Enveloped)
	Sha1      = TransformID(clib.Sha1)
	RsaSha1   = TransformID(clib.RsaSha1)
)

type Ctx struct {
	ptr uintptr // *C.xmlSecDSigCtx
}

type Signature struct {
	keyinfo    types.Node
	refnode    types.Node
	signmethod TransformID
	signnode   types.Node
}
