package xmlsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXmlSec(t *testing.T) {
	f := func() {
		Init()
		defer Shutdown()
	}

	if !assert.NotPanics(t, f, "Init + Shutdown should succeed") {
		return
	}
}

func TestXmlSecDSigCtx(t *testing.T) {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "Generating private key should succeed") {
		return
	}

	ctx, err := NewDSigCtx()
	if !assert.NoError(t, err, "NewDSigCtx should succeed") {
		return
	}
	defer ctx.Free()

	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	pemfile, err := ioutil.TempFile("", "xmlsec-test-")
	if !assert.NoError(t, err, "TempFile should succeed") {
		return
	}
	defer os.Remove(pemfile.Name())
	defer pemfile.Close()

	if !assert.NoError(t, pem.Encode(pemfile, pemkey), "Encoding to pem should succeed") {
		return
	}

	if !assert.NoError(t, pemfile.Sync(), "Sync should succeed") {
		return
	}

	key, err := LoadKeyFromFile(pemfile.Name(), KeyDataFormatPem)
	if !assert.NoError(t, err, "Loading key should succeed") {
		return
	}
	ctx.SetKey(key)
}