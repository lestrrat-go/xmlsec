package xmlsec

import "github.com/lestrrat/go-libxml2"

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

