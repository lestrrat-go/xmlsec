package key

import "crypto/dsa"

type DSA struct {
	key *dsa.PublicKey
}
