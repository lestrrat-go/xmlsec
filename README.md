# go-xmlsec

[![Build Status](https://travis-ci.org/lestrrat/go-xmlsec.svg?branch=master)](https://travis-ci.org/lestrrat/go-xmlsec)

[![GoDoc](https://godoc.org/github.com/lestrrat/go-xmlsec?status.svg)](https://godoc.org/github.com/lestrrat/go-xmlsec)

go-xmlsec is a Go binding for XML Security Library (https://www.aleksey.com/xmlsec/index.html)

## Status

* API still unstable.
* There's enough code to generate signatures for a libxml2 Document, and to verify it, but not much else.
* PRs, suggestions for more coverage welcome.

## Example

```go
import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "io/ioutil"
  "log"
  "os"

  "github.com/lestrrat/go-libxml2"
  "github.com/lestrrat/go-xmlsec"
)

func ExampleSignature_Sign() {
  xmlsec.Init()
  defer xmlsec.Shutdown()

  p := libxml2.NewParser(libxml2.XmlParseDTDLoad | libxml2.XmlParseDTDAttr | libxml2.XmlParseNoEnt)
  doc, err := p.ParseString(`<?xml version="1.0" encoding="UTF-8"?>
<Message><Data>Hello, World!</Data></Message>`)

  n, err := doc.DocumentElement()
  if err != nil {
    log.Printf("DocumentElement failed: %s", err)
    return
  }

  // n is the node where you want your signature to be
  // generated under
  sig, err := xmlsec.NewSignature(n, xmlsec.ExclC14N, xmlsec.RsaSha1, "")
  if err != nil {
    log.Printf("failed to create signature: %s", err)
    return
  }

  sig.AddReference(xmlsec.Sha1, "", "", "")
  sig.AddTransform(xmlsec.Enveloped)

  key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("failed to generate key: %s", err)
    return
  }

  if err := sig.Sign(key); err != nil {
    log.Printf("failed to sign: %s", err)
    return
  }

  log.Printf("%s", doc.Dump(true))
}


func ExampleDSigCtx_Sign() {
  xmlsec.Init()
  defer xmlsec.Shutdown()

  ctx, err := xmlsec.NewDSigCtx()
  if err != nil {
    log.Printf("Failed to create signature context: %s", err)
    return
  }
  defer ctx.Free()

  // This stuff isn't necessary if you already have a key file
  privkey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Printf("Failed to generate private key: %s", err)
    return
  }
  var pemkey = &pem.Block{
    Type:  "RSA PRIVATE KEY",
    Bytes: x509.MarshalPKCS1PrivateKey(privkey),
  }

  pemfile, err := ioutil.TempFile("", "xmlsec-test-")
  if err != nil {
    log.Printf("Failed to create temporary pemfile")
    return
  }
  defer os.Remove(pemfile.Name())
  defer pemfile.Close()

  if err := pem.Encode(pemfile, pemkey); err != nil {
    log.Printf("Failed to write to pemfile: %s", err)
    return
  }

  if err := pemfile.Sync(); err != nil {
    log.Printf("Failed to sync pemfile: %s", err)
    return
  }

  key, err := xmlsec.LoadKeyFromFile(pemfile.Name(), xmlsec.KeyDataFormatPem)
  if err != nil {
    log.Printf("Faild to load key: %s", err)
    return
  }
  ctx.SetKey(key)

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

  if err != nil {
    log.Printf("Failed to parse source XML: %s", err)
    return
  }
  defer doc.Free()

  if err := ctx.Sign(doc); err != nil {
    log.Printf("Failed to sign document: %s", err)
    return
  }

  log.Printf("%s", doc.Dump(true))
}
```

## Caveats

cgo and pkg-config sometimes have problems with quoting. For example, on my local
machine (OS X 10.10.5 + go 1.5.1), I get this:

```
shoebill% go test .
# github.com/lestrrat/go-xmlsec
In file included from <built-in>:326:
<command line>:1:24: warning: missing terminating '"' character [-Winvalid-pp-token]
```

If it annoys you, explicitly specifying `#cgo CFLAGS:` and `#cgo LDFLAGS:` may help,
but we don't do that in this library because it makes it unportable.

## See Also

* https://github.com/lestrrat/go-libxml2
* https://www.aleksey.com/xmlsec/index.html

## Credits

* Work on this library was generously sponsored by HDE Inc (https://www.hde.co.jp)
