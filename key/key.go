package key

import (
	"crypto/dsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
	"github.com/lestrrat/go-xmlsec"
)

// NewRSA creates a new RSA key representation for the public key
func NewRSA(pubkey *rsa.PublicKey) *RSA {
	return &RSA{key: pubkey}
}

func (key *RSA) Serialize() (string, error) {
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

func (key *RSA) MakeXMLNode(doc types.Document) (types.Node, error) {
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

	rsakeynode, err := doc.CreateElement(prefix + ":RSAKeyValue")
	if err != nil {
		return nil, err
	}
	kvnode.AddChild(rsakeynode)

	mnode, err := doc.CreateElement(prefix + ":Modulus")
	if err != nil {
		return nil, err
	}
	mnode.AppendText(base64.StdEncoding.EncodeToString(key.key.N.Bytes()))
	rsakeynode.AddChild(mnode)

	enode, err := doc.CreateElement(prefix + ":Exponent")
	if err != nil {
		return nil, err
	}

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(key.key.E))
  i := 0
  for ; i < len(data); i++ {
    if data[i] != 0x0 {
      break
    }
  }
	enode.AppendText(base64.StdEncoding.EncodeToString(data[i:]))
	rsakeynode.AddChild(enode)

	root.MakePersistent()

	return root, nil
}

// NewDSA creates a new DSA key representation for the public key
func NewDSA(pubkey *dsa.PublicKey) *DSA {
	return &DSA{key: pubkey}
}

// Serialize creates the XML representation for this DSA key
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

// MakeXMLNode creates a libxml2 node tree to represent this DSA key
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
