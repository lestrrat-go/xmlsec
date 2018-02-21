package crypto

import (
	"crypto/rsa"

	"github.com/lestrrat-go/libxml2/types"
	"github.com/lestrrat-go/xmlsec/clib"
)

func NewKeyManager() (*KeyManager, error) {
	mngrptr, err := clib.XMLSecKeysMngrCreate()
	if err != nil {
		return nil, err
	}

	return &KeyManager{ptr: mngrptr}, nil
}

func (km KeyManager) Pointer() uintptr {
	return km.ptr
}

func (km *KeyManager) Free() {
	clib.XMLSecKeysMngrDestroy(km)
}

func (km *KeyManager) GetKey(n types.Node) error {
	keyptr, err := clib.XMLSecKeysMngrGetKey(km, n)
	if err != nil {
		return err
	}
	km.AdoptKey(&Key{ptr: keyptr})
	return nil
}

// AdoptKey adds a key to the key manager
func (km *KeyManager) AdoptKey(key *Key) error {
	return clib.XMLSecKeysMngrAdoptKey(km, key)
}

func (km *KeyManager) LoadKeyFromRSAPrivateKey(privkey *rsa.PrivateKey) error {
	key, err := LoadKeyFromRSAPrivateKey(privkey)
	if err != nil {
		return err
	}
	return km.AdoptKey(key)
}

func (km *KeyManager) LoadCert(buf []byte, format KeyDataFormat, typ KeyDataType) error {
	return clib.XMLSecKeysMngrCertLoadMemory(km, buf, clib.KeyDataFormat(format), clib.KeyDataType(typ))
}
