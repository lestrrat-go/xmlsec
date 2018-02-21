package dsig

import (
	"github.com/lestrrat-go/libxml2/parser"
	"github.com/lestrrat-go/libxml2/xpath"
	"github.com/lestrrat-go/xmlsec"
	"github.com/lestrrat-go/xmlsec/clib"
	"github.com/lestrrat-go/xmlsec/crypto"
)

func NewSignatureVerify() (*SignatureVerify, error) {
	return &SignatureVerify{}, nil
}

func (v *SignatureVerify) LoadKeyFromFile(file string, format crypto.KeyDataFormat) error {
	k, err := crypto.LoadKeyFromFile(file, format)
	if err != nil {
		return err
	}
	if v.key != nil {
		v.key.Free()
	}
	v.key = k
	return nil
}

func (v *SignatureVerify) Free() {
	if v.key == nil {
		return
	}
	v.key.Free()
}

func (v *SignatureVerify) Verify(buf []byte) error {
	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.Parse(buf)
	if err != nil {
		return err
	}
	defer doc.Free()

	mngr, err := crypto.NewKeyManager()
	if err != nil {
		return err
	}
	defer mngr.Free()

	ctx, err := NewCtx(mngr)
	if err != nil {
		return err
	}
	defer ctx.Free()

	root, err := doc.DocumentElement()
	if err != nil {
		return err
	}
	signode, err := clib.FindSignatureNode(root)
	if err != nil {
		return err
	}

	// Create a key manager, load keys from KeyInfo
	prefix, err := signode.LookupNamespacePrefix(xmlsec.DSigNs)
	if err != nil {
		return err
	}
	if prefix == "" {
		prefix = xmlsec.Prefix
	}

	xpc, err := xpath.NewContext(signode)
	if err != nil {
		return err
	}

	xpc.RegisterNS(prefix, xmlsec.Prefix)

	iter := xpath.NodeIter(xpc.Find("//" + prefix + ":KeyInfo"))
	for iter.Next() {
		n := iter.Node()
		if err := mngr.GetKey(n); err != nil {
			return err
		}
	}

	if key := v.key; key != nil {
		cpy, err := key.Copy()
		if err != nil {
			return err
		}

		if err := ctx.SetKey(cpy); err != nil {
			return err
		}
	}

	return ctx.Verify(doc)
}

func (v *SignatureVerify) VerifyString(buf string) error {
	return v.Verify([]byte(buf))
}
