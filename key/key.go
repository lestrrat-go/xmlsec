package key

import (
	"crypto/dsa"
	"encoding/base64"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-xmlsec"
)

func NewDSA(pubkey *dsa.PublicKey) *DSA {
	return &DSA{key: pubkey}
}

func (key *DSA) Serialize() (string, error) {
	doc := dom.CreateDocument()
	defer doc.AutoFree()
	doc.MakeMortal()

	root, err := key.MakeXMLNode(doc)
	if err != nil {
		return "", err
	}
	doc.SetDocumentElement(root)

	doc.MakePersistent()

	return doc.Dump(true), nil
}

func (key *DSA) MakeXMLNode(doc types.Document) (types.Node, error) {
	var root types.Node
	var err error

	prefix, err := doc.LookupNamespacePrefix(xmlsec.DSigNs)
	if err != nil {
		// namespace does not exist. make me a namespace
		root, err = doc.CreateElementNS(xmlsec.DSigNs, xmlsec.Prefix+":KeyInfo")
		if err != nil {
			return nil, err
		}
		prefix = xmlsec.Prefix
	} else {
		root, err = doc.CreateElement(prefix + ":KeyInfo")
		if err != nil {
			return nil, err
		}
	}
	defer root.AutoFree()
	root.MakeMortal()

	kvnode, err := doc.CreateElement(prefix + ":KeyValue")
	if err != nil {
		return nil, err
	}
	root.AddChild(kvnode)

	dsakeynode, err := doc.CreateElement(prefix + ":DSAKeyValue")
	if err != nil {
		return nil, err
	}
	kvnode.AddChild(dsakeynode)

	pnode, err := doc.CreateElement(prefix + ":P")
	if err != nil {
		return nil, err
	}
	pnode.AppendText(base64.StdEncoding.EncodeToString(key.key.P.Bytes()))
	dsakeynode.AddChild(pnode)

	qnode, err := doc.CreateElement(prefix + ":Q")
	if err != nil {
		return nil, err
	}
	qnode.AppendText(base64.StdEncoding.EncodeToString(key.key.Q.Bytes()))
	dsakeynode.AddChild(qnode)

	gnode, err := doc.CreateElement(prefix + ":G")
	if err != nil {
		return nil, err
	}
	gnode.AppendText(base64.StdEncoding.EncodeToString(key.key.G.Bytes()))
	dsakeynode.AddChild(gnode)

	ynode, err := doc.CreateElement(prefix + ":Y")
	if err != nil {
		return nil, err
	}
	ynode.AppendText(base64.StdEncoding.EncodeToString(key.key.Y.Bytes()))
	dsakeynode.AddChild(ynode)

	root.MakePersistent()

	return root, nil
}
