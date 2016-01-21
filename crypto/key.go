package crypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/lestrrat/go-xmlsec/clib"
)

func (k Key) Pointer() uintptr {
	return k.ptr
}

func LoadKeyFromFile(file string, format KeyDataFormat) (*Key, error) {
	ptr, err := clib.XMLSecCryptoAppKeyLoad(file, clib.KeyDataFormat(format))
	if err != nil {
		return nil, err
	}
	return &Key{ptr: ptr}, nil
}

func LoadKeyFromBytes(data []byte, format KeyDataFormat) (*Key, error) {
	ptr, err := clib.XMLSecCryptoAppKeyLoadMemory(data, clib.KeyDataFormat(format))
	if err != nil {
		return nil, err
	}
	return &Key{ptr: ptr}, nil
}

func LoadKeyFromRSAPrivateKey(privkey *rsa.PrivateKey) (*Key, error) {
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, pemkey); err != nil {
		return nil, err
	}

	return LoadKeyFromBytes(buf.Bytes(), KeyDataFormatPem)
}

func LoadCertFromFile(fn string, format KeyDataFormat) (*Key, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	defer func() {
		if key == nil || err == nil {
			return
		}
		key.Free()
	}()

	if err = key.LoadCertFromFile(fn, format); err != nil {
		return nil, err
	}
	return key, nil
}

func (k *Key) LoadCertFromFile(fn string, format KeyDataFormat) error {
	return clib.XMLSecCryptoAppKeyCertLoad(k, fn, clib.KeyDataFormat(format))
}

func NewKey() (*Key, error) {
	ptr, err := clib.XMLSecKeyCreate()
	if err != nil {
		return nil, err
	}
	return &Key{ptr: ptr}, nil
}

func (k *Key) Free() {
	clib.XMLSecKeyDestroy(k)
}

func (k *Key) Copy() (*Key, error) {
	keyptr, err := clib.XMLSecKeyDuplicate(k)
	if err != nil {
		return nil, err
	}
	return &Key{ptr: keyptr}, nil
}

func (k Key) HasX509() error {
	return clib.XMLSecKeyHasX509(k)
}

func (k Key) HasRsaKey() error {
	return clib.XMLSecKeyHasRsaKey(k)
}

func (k Key) HasDsaKey() error {
	return clib.XMLSecKeyHasDsaKey(k)
}

func (k Key) HasEcdsaKey() error {
	return clib.XMLSecKeyHasEcdsaKey(k)
}

