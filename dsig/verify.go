package dsig

import (
	"github.com/lestrrat/go-libxml2/parser"
	"github.com/lestrrat/go-xmlsec/crypto"
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

	ctx, err := NewCtx()
	if err != nil {
		return err
	}
	defer ctx.Free()

	cpy, err := v.key.Copy()
	if err != nil {
		return err
	}
	if err := ctx.SetKey(cpy); err != nil {
		return err
	}

	return ctx.Verify(doc)
}

func (v *SignatureVerify) VerifyString(buf string) error {
	return v.Verify([]byte(buf))
}
