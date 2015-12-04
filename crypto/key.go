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

func LoadKeyFromFile(file string, format clib.KeyDataFormat) (*Key, error) {
	ptr, err := clib.XMLSecCryptoAppKeyLoad(file, format)
	if err != nil {
		return nil, err
	}
	return &Key{ptr: ptr}, nil
}

func LoadKeyFromBytes(data []byte, format clib.KeyDataFormat) (*Key, error) {
	ptr, err := clib.XMLSecCryptoAppKeyLoadMemory(data, format)
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

func (k *Key) LoadCertFromFile(fn string, format clib.KeyDataFormat) error {
	return clib.XMLSecCryptoAppKeyCertLoad(k, fn, format)
}
