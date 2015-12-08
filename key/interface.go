/*

Package key contains utilities to create KeyDescriptor nodes on the fly.
Normally xmlsec would handle this, but xmlsec expects certain nodes to
be the parent of ds:KeyInfo nodes. This package gives you a simple
programatic way to insert nodes in, for example, IDPSSODescriptor
nodes.

*/
package key

import (
	"crypto/dsa"
	"crypto/rsa"
)

// RSA represents a RSA key
type RSA struct {
	key *rsa.PublicKey
}

// DSA represents a DSA key
type DSA struct {
	key *dsa.PublicKey
}
