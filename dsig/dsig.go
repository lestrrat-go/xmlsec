package dsig

import (
	"errors"

	"github.com/lestrrat-go/libxml2/types"
	"github.com/lestrrat-go/xmlsec/clib"
	"github.com/lestrrat-go/xmlsec/crypto"
)

// NewCtx creates a new XML Signature Context
func NewCtx(mngr *crypto.KeyManager) (*Ctx, error) {
	var ptr uintptr
	var err error
	if mngr == nil {
		ptr, err = clib.XMLSecDSigCtxCreate(nil)
	} else {
		ptr, err = clib.XMLSecDSigCtxCreate(mngr)
	}

	if err != nil {
		return nil, err
	}
	return &Ctx{ptr: ptr}, nil
}

func (d Ctx) Pointer() uintptr {
	return d.ptr
}

// Free releases the underlying C structure
func (d *Ctx) Free() error {
	return clib.XMLSecDSigCtxDestroy(d)
}

func (d *Ctx) SetKey(key clib.PtrSource) error {
	return clib.XMLSecDSigCtxSetKey(d, key)
}

// Sign signs the given document. It automatically searches
// for the "Signature" node with the namespace "http://www.w3.org/2000/09/xmldsig#".
func (d *Ctx) Sign(doc types.Document) error {
	return clib.XMLSecDSigCtxSignDocument(d, doc)
}

// SignNode signs the given node.
func (d *Ctx) SignNode(n types.Node) error {
	return clib.XMLSecDSigCtxSignNode(d, n)
}

// Verify verifies the signature in the given document. It automatically searches
// for the "Signature" node with the namespace "http://www.w3.org/2000/09/xmldsig#".
func (d *Ctx) Verify(doc types.Document) error {
	return clib.XMLSecDSigCtxVerifyDocument(d, doc)
}

// VerifyNode verifies the signature in the given node
func (d *Ctx) VerifyNode(n types.Node) error {
	return clib.XMLSecDSigCtxVerifyNode(d, n)
}

// NewSignature creates a Signature object.
func NewSignature(n types.Node, c14n, sig TransformID, id string) (*Signature, error) {
	doc, err := n.OwnerDocument()
	if err != nil {
		return nil, err
	}

	signnode, err := clib.XMLSecTmplSignatureCreateNsPref(
		doc,
		clib.TransformID(c14n),
		clib.TransformID(sig),
		id,
		clib.Prefix,
	)
	if err != nil {
		return nil, err
	}

	n.AddChild(signnode)

	return &Signature{
		signmethod: sig,
		signnode:   signnode,
	}, nil
}

// AddReference adds a Reference node to the appropriate location
func (s *Signature) AddReference(digestMethod TransformID, id, uri, nodeType string) error {
	rn, err := clib.XMLSecTmplSignatureAddReference(
		s.signnode,
		clib.TransformID(digestMethod),
		id,
		uri,
		nodeType,
	)
	if err != nil {
		return err
	}

	s.refnode = rn
	return nil
}

// AddTransform adds a Transform node to the appropriate location
func (s *Signature) AddTransform(transformID TransformID) error {
	if s.refnode == nil {
		return errors.New("missing reference node: did you call AddReference() first?")
	}

	if _, err := clib.XMLSecTmplReferenceAddTransform(s.refnode, clib.TransformID(transformID)); err != nil {
		return err
	}
	return nil
}

// EnsureKeyInfo adds a KeyInfo node to the apprpriate location
func (s *Signature) EnsureKeyInfo(ids ...string) error {
	if s.keyinfo != nil {
		return nil
	}

	var id string
	if len(ids) > 0 {
		id = ids[0]
	}
	keyinfo, err := clib.XMLSecTmplSignatureEnsureKeyInfo(s.signnode, id)
	if err != nil {
		return err
	}
	s.keyinfo = keyinfo
	return nil
}

// AddKeyValue adds KeyValue nodes to appropriate location. Before adding
// these nodes, EnsureKeyInfo is called to makes ure KeyInfo node is
// created and added.
func (s *Signature) AddKeyValue() error {
	s.EnsureKeyInfo()
	if _, err := clib.XMLSecTmplKeyInfoAddKeyValue(s.keyinfo); err != nil {
		return err
	}
	return nil
}

// AddX509Data adds a X509Data node to the apprpriate location
func (s *Signature) AddX509Data() error {
	s.EnsureKeyInfo()
	if _, err := clib.XMLSecTmplKeyInfoAddX509Data(s.keyinfo); err != nil {
		return err
	}
	return nil
}

// Sign populates the signature for the payload. The signature is generated
// using the specified key
func (s *Signature) Sign(key *crypto.Key) error {
	km, err := crypto.NewKeyManager()
	ctx, err := NewCtx(km)
	if err != nil {
		return err
	}
	defer ctx.Free()
	defer km.Free()

	if err := km.AdoptKey(key); err != nil {
		return err
	}

	return ctx.SignNode(s.signnode)
}
