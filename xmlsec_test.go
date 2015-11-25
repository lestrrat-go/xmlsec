package xmlsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"

	"github.com/lestrrat/go-libxml2"
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

func writePemFile(b *pem.Block) (string, error) {
	pemfile, err := ioutil.TempFile("", "xmlsec-test-")
	if err != nil {
		return "", err
	}
	defer pemfile.Close()

	if err := pem.Encode(pemfile, b); err != nil {
		return "", err
	}

	if err := pemfile.Sync(); err != nil {
		return "", err
	}

	return pemfile.Name(), nil
}

func writePrivateKey(privkey *rsa.PrivateKey) (string, error) {
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	return writePemFile(pemkey)
}

func writePublicKey(pubkey *rsa.PublicKey) (string, error) {
	marshaled, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshaled,
	}

	return writePemFile(pemkey)
}

func TestXmlSecDSigCtx(t *testing.T) {
	Init()
	defer Shutdown()

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.NoError(t, err, "Generating private key should succeed") {
		return
	}

	privfile, err := writePrivateKey(privkey)
	if !assert.NoError(t, err, "Writing private key should succeed") {
		return
	}
	defer os.Remove(privfile)

	pubfile, err := writePublicKey(&privkey.PublicKey)
	if !assert.NoError(t, err, "Writing public key should succeed") {
		return
	}
	defer os.Remove(pubfile)

	p := libxml2.NewParser(libxml2.XmlParseDTDLoad | libxml2.XmlParseDTDAttr | libxml2.XmlParseNoEnt)
	doc, err := p.ParseString(`<?xml version="1.0" encoding="UTF-8"?>
<!-- XML Security Library example: Simple signature template file for sign1 example.  -->
<Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <KeyName/>
    </KeyInfo>
  </Signature>
</Envelope>`)

	if !assert.NoError(t, err, "Parsing template should succeed") {
		return
	}
	defer doc.Free()

	{
		ctx, err := NewDSigCtx()
		if !assert.NoError(t, err, "NewDSigCtx should succeed") {
			return
		}
		defer ctx.Free()

		key, err := LoadKeyFromFile(privfile, KeyDataFormatPem)
		if !assert.NoError(t, err, "Loading private key '%s' should succeed", privfile) {
			return
		}
		ctx.SetKey(key)

		if !assert.NoError(t, ctx.Sign(doc), "Sign should succeed") {
			return
		}
	}

	t.Logf("%s", doc.Dump(true))

	{
		ctx, err := NewDSigCtx()
		if !assert.NoError(t, err, "NewDSigCtx should succeed") {
			return
		}
		defer ctx.Free()

		key, err := LoadKeyFromFile(pubfile, KeyDataFormatPem)
		if !assert.NoError(t, err, "Loading public key '%s' should succeed", pubfile) {
			return
		}
		ctx.SetKey(key)

		if !assert.NoError(t, ctx.Verify(doc), "Verify should succeed") {
			return
		}
	}
}