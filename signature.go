package xmlsec

import (
	"crypto/rsa"
	"errors"

	"github.com/lestrrat/go-libxml2"
)

// NewDSigCtx creates a new XML Signature Context
func NewDSigCtx() (*DSigCtx, error) {
	return xmlSecDSigCtxCreate()
}

// Free releases the underlying C structure
func (d *DSigCtx) Free() error {
	return xmlSecDSigCtxDestroy(d)
}

// Sign signs the given document. It automatically searches
// for the "Signature" node with the namespace "http://www.w3.org/2000/09/xmldsig#".
func (d *DSigCtx) Sign(doc *libxml2.Document) error {
	return xmlSecDSigCtxSignDocument(d, doc)
}

// SignNode signs the given node.
func (d *DSigCtx) SignNode(n libxml2.Node) error {
	return xmlSecDSigCtxSignNode(d, n)
}

// Verify verifies the signature in the given document. It automatically searches
// for the "Signature" node with the namespace "http://www.w3.org/2000/09/xmldsig#".
func (d *DSigCtx) Verify(doc *libxml2.Document) error {
	return xmlSecDSigCtxVerifyDocument(d, doc)
}

// VerifyNode verifies the signature in the given node
func (d *DSigCtx) VerifyNode(n libxml2.Node) error {
	return xmlSecDSigCtxVerifyNode(d, n)
}

func NewSignature(n libxml2.Node, c14n, sig TransformID, id string) (*Signature, error) {
	doc, err := n.OwnerDocument()
	if err != nil {
		return nil, err
	}

	signnode, err := xmlSecTmplSignatureCreate(doc, c14n, sig, id)
	if err != nil {
		return nil, err
	}

	n.AddChild(signnode)

	return &Signature{
		signmethod: sig,
		signnode:   signnode,
	}, nil
}

func (s *Signature) AddReference(digestMethod TransformID, id, uri, nodeType string) error {
	rn, err := xmlSecTmplSignatureAddReference(s.signnode, digestMethod, id, uri, nodeType)
	if err != nil {
		return err
	}

	s.refnode = rn
	return nil
}

func (s *Signature) AddTransform(transformID TransformID) error {
	if s.refnode == nil {
		return errors.New("missing reference node: did you call AddReference() first?")
	}

	if _, err := xmlSecTmplReferenceAddTransform(s.refnode, transformID); err != nil {
		return err
	}
	return nil
}

func (s *Signature) EnsureKeyInfo(ids ...string) error {
	var id string
	if len(ids) > 0 {
		id = ids[0]
	}
	keyinfo, err := xmlSecTmplSignatureEnsureKeyInfo(s.signnode, id)
	if err != nil {
		return err
	}
	s.keyinfo = keyinfo
	return nil
}

func (s *Signature) AddX509Data() error {
	if _, err := xmlSecTmplKeyInfoAddX509Data(s.keyinfo); err != nil {
		return err
	}
	return nil
}

func (s *Signature) Sign(key interface{}) error {
	ctx, err := NewDSigCtx()
	if err != nil {
		return err
	}
	defer ctx.Free()

	var seckey *Key
	switch s.signmethod {
	case RsaSha1:
		seckey, err = LoadKeyFromRSAPrivateKey(key.(*rsa.PrivateKey))
		if err != nil {
			return err
		}
	default:
		return ErrInvalidKeyType
	}

	if err := ctx.SetKey(seckey); err != nil {
		return err
	}

	return ctx.SignNode(s.signnode)
}
