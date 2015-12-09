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

func (k *Key) LoadCertFromFile(fn string, format KeyDataFormat) error {
	return clib.XMLSecCryptoAppKeyCertLoad(k, fn, clib.KeyDataFormat(format))
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
