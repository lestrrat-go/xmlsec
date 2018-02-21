package key

import (
	"crypto/dsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/lestrrat-go/libxml2"
	"github.com/lestrrat-go/libxml2/dom"
	"github.com/lestrrat-go/libxml2/parser"
	"github.com/lestrrat-go/libxml2/types"
	"github.com/lestrrat-go/xmlsec"
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

func Parse(buf []byte) (Key, error) {
	doc, err := libxml2.Parse(buf, parser.XMLParseNoBlanks)
	if err != nil {
		return nil, err
	}

	root, err := doc.DocumentElement()
	if err != nil {
		return nil, err
	}

	return Construct(root)
}

// Construct takes the node and creates a new Key. The node must be
// a KeyInfo node
func Construct(n types.Node) (Key, error) {
	ne, ok := n.(types.Element)
	if !ok || ne.LocalName() != "KeyInfo" {
		return nil, errors.New("invalid node (expected KeyInfo)")
	}

	kv, err := ne.FirstChild()
	if err != nil {
		return nil, err
	}
	kve, ok := kv.(types.Element)
	if !ok || kve.LocalName() != "KeyValue" {
		return nil, errors.New("invalid node (expected KeyValue)")
	}

	kn, err := kv.FirstChild()
	if err != nil {
		return nil, err
	}
	kne, ok := kn.(types.Element)
	if !ok {
		return nil, errors.New("invalid node (expected element node)")
	}

	switch kne.LocalName() {
	case "RSAKeyValue":
		pubkey := &rsa.PublicKey{}
		children, err := kne.ChildNodes()
		if err != nil {
			return nil, err
		}

		for _, x := range children {
			n, ok := x.(types.Element)
			if !ok {
				return nil, errors.New("invalid under RSAKeyValue")
			}
			switch n.LocalName() {
			case "Modulus":
				v, err := base64.StdEncoding.DecodeString(n.TextContent())
				if err != nil {
					return nil, err
				}
				pubkey.N = (&big.Int{}).SetBytes(v)
			case "Exponent":
				v, err := base64.StdEncoding.DecodeString(n.TextContent())
				if err != nil {
					return nil, err
				}
				if len(v) < 64 {
					b := make([]byte, 64)
					copy(b[64-len(v):], v)
					v = b
				}
				pubkey.E = int(binary.BigEndian.Uint64(v))
			}
		}
		return NewRSA(pubkey), nil
	case "DSAKeyValue":
		pubkey := &dsa.PublicKey{}
		children, err := kne.ChildNodes()
		if err != nil {
			return nil, err
		}

		for _, x := range children {
			n, ok := x.(types.Element)
			if !ok {
				return nil, errors.New("invalid under DSAKeyValue")
			}
			switch n.LocalName() {
			case "P":
				v, err := base64.StdEncoding.DecodeString(n.TextContent())
				if err != nil {
					return nil, err
				}
				pubkey.P = (&big.Int{}).SetBytes(v)
			case "Q":
				v, err := base64.StdEncoding.DecodeString(n.TextContent())
				if err != nil {
					return nil, err
				}
				pubkey.Q = (&big.Int{}).SetBytes(v)
			case "G":
				v, err := base64.StdEncoding.DecodeString(n.TextContent())
				if err != nil {
					return nil, err
				}
				pubkey.G = (&big.Int{}).SetBytes(v)
			case "Y":
				v, err := base64.StdEncoding.DecodeString(n.TextContent())
				if err != nil {
					return nil, err
				}
				pubkey.Y = (&big.Int{}).SetBytes(v)
			}
		}
		return NewDSA(pubkey), nil
	default:
		return nil, errors.New("invalid node expected: DSAKeyValue or RSAKeyValue")
	}
}
