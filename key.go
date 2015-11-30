package xmlsec

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func LoadKeyFromFile(file string, format KeyDataFormat) (*Key, error) {
	return xmlSecCryptoAppKeyLoad(file, format)
}

func LoadKeyFromBytes(data []byte, format KeyDataFormat) (*Key, error) {
	return xmlSecCryptoAppKeyLoadMemory(data, format)
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
	return xmlSecCryptoAppKeyCertLoad(k, fn, format)
}
