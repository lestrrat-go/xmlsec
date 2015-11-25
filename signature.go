package xmlsec

import "github.com/lestrrat/go-libxml2"

func NewDSigCtx() (*DSigCtx, error) {
	return xmlSecDSigCtxCreate()
}

func (d *DSigCtx) Free() error {
	return xmlSecDSigCtxDestroy(d)
}

func (d *DSigCtx) Sign(doc *libxml2.Document) error {
	return xmlSecDSigCtxSignDocument(d, doc)
}
