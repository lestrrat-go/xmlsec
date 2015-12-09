package xmlsec_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/parser"
	"github.com/lestrrat/go-xmlsec"
	"github.com/lestrrat/go-xmlsec/crypto"
	"github.com/lestrrat/go-xmlsec/dsig"
	"github.com/stretchr/testify/assert"
)

func TestXmlSec(t *testing.T) {
	f := func() {
		xmlsec.Init()
		defer xmlsec.Shutdown()
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
	xmlsec.Init()
	defer xmlsec.Shutdown()

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

	src := `<?xml version="1.0" encoding="UTF-8"?>
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
</Envelope>`

	p := parser.New(parser.XMLParseDTDLoad | parser.XMLParseDTDAttr | parser.XMLParseNoEnt)
	doc, err := p.ParseString(src)

	if !assert.NoError(t, err, "Parsing template should succeed") {
		return
	}
	defer doc.Free()

	{
		ctx, err := dsig.NewCtx()
		if !assert.NoError(t, err, "dsig.NewCtx should succeed") {
			return
		}
		defer ctx.Free()

		key, err := crypto.LoadKeyFromFile(privfile, crypto.KeyDataFormatPem)
		if !assert.NoError(t, err, "Loading private key '%s' should succeed", privfile) {
			return
		}
		ctx.SetKey(key)

		if !assert.NoError(t, ctx.Sign(doc), "Sign should succeed") {
			return
		}
	}

	signed := doc.String()
	t.Logf("%s", signed)

	{
		ctx, err := dsig.NewCtx()
		if !assert.NoError(t, err, "dsig.NewCtx should succeed") {
			return
		}
		defer ctx.Free()

		key, err := crypto.LoadKeyFromFile(pubfile, crypto.KeyDataFormatPem)
		if !assert.NoError(t, err, "Loading public key '%s' should succeed", pubfile) {
			return
		}
		ctx.SetKey(key)

		if !assert.NoError(t, ctx.Verify(doc), "Verify should succeed") {
			return
		}
	}

	{
		verify, err := dsig.NewSignatureVerify()
		if !assert.NoError(t, err, "NewSignatureVerify succeeds") {
			return
		}

		if !assert.NoError(t, verify.LoadKeyFromFile(pubfile, crypto.KeyDataFormatPem), "LoadKeyFromFile succeeds") {
			return
		}

		if !assert.NoError(t, verify.VerifyString(signed), "VerifyString succeeds") {
			return
		}
		if !assert.NoError(t, verify.Verify([]byte(signed)), "Verify succeeds") {
			return
		}
	}
}

func TestSignature(t *testing.T) {
	xmlsec.Init()
	defer xmlsec.Shutdown()

	doc := dom.CreateDocument()
	defer doc.Free()

	message, err := doc.CreateElement("Message")
	if !assert.NoError(t, err, "CreateElement succeeds") {
		return
	}
	doc.SetDocumentElement(message)

	data, err := doc.CreateElement("Data")
	if !assert.NoError(t, err, "CreateElement succeeds") {
		return
	}
	message.AddChild(data)
	data.AppendText("Hello, World!")

	sig, err := dsig.NewSignature(message, dsig.ExclC14N, dsig.RsaSha1, "")
	if !assert.NoError(t, err, "NewSignature succeeds") {
		return
	}

	if !assert.NoError(t, sig.AddReference(dsig.Sha1, "", "", ""), "AddReference succeeds") {
		return
	}

	if !assert.NoError(t, sig.AddTransform(dsig.Enveloped), "AddTransform succeeds") {
		return
	}

	if !assert.NoError(t, sig.EnsureKeyInfo(), "EnsureKeyInfo succeeds") {
		return
	}

	if !assert.NoError(t, sig.AddX509Data(), "AddX509Data succeeds") {
		return
	}

	keyfile := filepath.Join("test", "key.pem")
	certfile := filepath.Join("test", "cert.pem")
	key, err := crypto.LoadKeyFromFile(keyfile, crypto.KeyDataFormatPem)
	if !assert.NoError(t, err, "Load key from file succeeds") {
		return
	}

	key.LoadCertFromFile(certfile, crypto.KeyDataFormatPem)

	if !assert.NoError(t, sig.Sign(key), "Sign succeeds") {
		return
	}

	t.Logf("%s", doc.Dump(true))
}