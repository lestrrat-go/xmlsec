/*
Package clib is the library that does all the dirty work interacting
with the xmlsec C interface (https://www.aleksey.com/xmlsec/index.html)

In order to use this library, you need go-libxml2 (https://github.com/lestrrat/go-libxml2)
*/

package clib

/*
#cgo pkg-config: xmlsec1
#include <stdlib.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlstring.h>
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/transforms.h>
#include <xmlsec/crypto.h>

static inline xmlChar* to_xmlcharptr(const char *s) {
  return (xmlChar *) s;
}

static inline char * to_charptr(const xmlChar *s) {
  return (char *) s;
}

static xsltSecurityPrefsPtr xsltSecPrefs = NULL;
static int
go_xmlsec_init() {
  xmlIndentTreeOutput = 1;
  xsltSecPrefs = xsltNewSecurityPrefs();
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
  xsltSetDefaultSecurityPrefs(xsltSecPrefs);

  if(xmlSecInit() < 0) {
    return -1;
  }

  if(xmlSecCheckVersion() != 1) {
    return -1;
  }

  if(xmlSecCryptoAppInit(NULL) < 0) {
    return -1;
  }

  if(xmlSecCryptoInit() < 0) {
    fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
    return -1;
  }

	return 0;
}

static void
go_xmlsec_shutdown() {
  xmlSecCryptoShutdown();
  xmlSecCryptoAppShutdown();
  xmlSecShutdown();
  xsltFreeSecurityPrefs(xsltSecPrefs);
  xsltCleanupGlobals();
}

static inline xmlSecTransformId MY_Sha1Id() {
	return xmlSecTransformSha1Id;
}

static inline xmlSecTransformId MY_RsaSha1Id() {
	return xmlSecTransformRsaSha1Id;
}

*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/lestrrat/go-libxml2/clib"
	"github.com/lestrrat/go-libxml2/dom"
	"github.com/lestrrat/go-libxml2/types"
)

type KeyDataFormat int

const (
	KeyDataFormatUnknown  KeyDataFormat = C.xmlSecKeyDataFormatUnknown
	KeyDataFormatBinary                 = C.xmlSecKeyDataFormatBinary
	KeyDataFormatPem                    = C.xmlSecKeyDataFormatPem
	KeyDataFormatDer                    = C.xmlSecKeyDataFormatDer
	KeyDataFormatPkcs8Pem               = C.xmlSecKeyDataFormatPkcs8Pem
	KeyDataFormatPkcs8Der               = C.xmlSecKeyDataFormatPkcs8Der
	KeyDataFormatPkcs12                 = C.xmlSecKeyDataFormatPkcs12
	KeyDataFormatCertPem                = C.xmlSecKeyDataFormatCertPem
	KeyDataFormatCertDer                = C.xmlSecKeyDataFormatCertDer
)

type TransformID struct {
	ptr C.xmlSecTransformId
}

var (
	ExclC14N  = TransformID{ptr: C.xmlSecTransformExclC14NGetKlass()}
	Enveloped = TransformID{ptr: C.xmlSecTransformEnvelopedGetKlass()}
	Sha1      = TransformID{ptr: C.MY_Sha1Id()}
	RsaSha1   = TransformID{ptr: C.MY_RsaSha1Id()}
)

func XMLSecInit() error {
	if C.go_xmlsec_init() < C.int(0) {
		return errors.New("failed to initialize")
	}
	return nil
}

func XMLSecShutdown() error {
	C.go_xmlsec_shutdown()
	return nil
}

func xmlCharToString(s *C.xmlChar) string {
	return C.GoString(C.to_charptr(s))
}

func stringToXMLChar(s string) *C.xmlChar {
	return C.to_xmlcharptr(C.CString(s))
}

func validNodePtr(n types.Node) (*C.xmlNode, error) {
	if n == nil {
		return nil, clib.ErrInvalidNode
	}

	if ptr := n.Pointer(); ptr != 0 {
		return (*C.xmlNode)(unsafe.Pointer(ptr)), nil
	}
	return nil, clib.ErrInvalidNode
}

func validDSigCtxPtr(ctx PtrSource) (*C.xmlSecDSigCtx, error) {
	if ctx == nil {
		return nil, ErrInvalidDSigCtx
	}

	if ptr := ctx.Pointer(); ptr != 0 {
		return (*C.xmlSecDSigCtx)(unsafe.Pointer(ptr)), nil
	}

	return nil, ErrInvalidDSigCtx
}

func validKeyPtr(key PtrSource) (*C.xmlSecKey, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}

	if ptr := key.Pointer(); ptr != 0 {
		return (*C.xmlSecKey)(unsafe.Pointer(ptr)), nil
	}

	return nil, ErrInvalidKey
}

func XMLSecDSigCtxCreate() (uintptr, error) {
	ctx := C.xmlSecDSigCtxCreate(nil)
	if ctx == nil {
		return 0, errors.New("failed to create DSigCtx")
	}
	return uintptr(unsafe.Pointer(ctx)), nil
}

func XMLSecDSigCtxDestroy(ctx PtrSource) error {
	ctxptr, err := validDSigCtxPtr(ctx)
	if err != nil {
		return err
	}

	C.xmlSecDSigCtxDestroy(ctxptr)
	return nil
}

func XMLSecCryptoAppKeyLoadMemory(buf []byte, format KeyDataFormat) (uintptr, error) {
	key := C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&buf[0])),
		(C.xmlSecSize)(C.int(len(buf))),
		(C.xmlSecKeyDataFormat)(format),
		nil,
		nil,
		nil,
	)
	if key == nil {
		return 0, errors.New("failed to load key")
	}
	return uintptr(unsafe.Pointer(key)), nil
}

func XMLSecCryptoAppKeyLoad(file string, format KeyDataFormat) (uintptr, error) {
	cfile := C.CString(file)
	defer C.free(unsafe.Pointer(cfile))
	key := C.xmlSecCryptoAppKeyLoad(cfile, (C.xmlSecKeyDataFormat)(format), nil, nil, nil)
	if key == nil {
		return 0, errors.New("failed to load key")
	}

	if C.xmlSecKeySetName(key, (*C.xmlChar)(unsafe.Pointer(cfile))) < C.int(0) {
		return 0, errors.New("failed to set key name")
	}

	return uintptr(unsafe.Pointer(key)), nil
}

func XMLSecDSigCtxSetKey(ctx PtrSource, key PtrSource) error {
	ctxptr, err := validDSigCtxPtr(ctx)
	if err != nil {
		return err
	}

	keyptr, err := validKeyPtr(key)
	if err != nil {
		return err
	}

	ctxptr.signKey = keyptr
	return nil
}

func XMLSecDSigCtxSignRaw(ctxptr *C.xmlSecDSigCtx, nodeptr *C.xmlNode) error {
	if C.xmlSecDSigCtxSign(ctxptr, nodeptr) < C.int(0) {
		return errors.New("failed to sign node")
	}
	return nil
}

func XMLSecDSigCtxSignNode(ctx PtrSource, n types.Node) error {
	ctxptr, err := validDSigCtxPtr(ctx)
	if err != nil {
		return err
	}

	nodeptr, err := validNodePtr(n)
	if err != nil {
		return err
	}

	return XMLSecDSigCtxSignRaw(ctxptr, nodeptr)
}

func XMLSecDSigCtxSignDocument(ctx PtrSource, doc types.Document) error {
	ctxptr, err := validDSigCtxPtr(ctx)
	if err != nil {
		return err
	}

	root, err := doc.DocumentElement()
	if err != nil {
		return err
	}

	rootptr, err := validNodePtr(root)
	if err != nil {
		return err
	}

	cname := stringToXMLChar(SignatureNode)
	cns := stringToXMLChar(DSigNs)
	defer C.free(unsafe.Pointer(cname))
	defer C.free(unsafe.Pointer(cns))

	nodeptr := C.xmlSecFindNode(rootptr, cname, cns)
	if nodeptr == nil {
		return errors.New("failed to find start node")
	}

	return XMLSecDSigCtxSignRaw(ctxptr, nodeptr)
}

func XMLSecDSigCtxVerifyRaw(ctxptr *C.xmlSecDSigCtx, nodeptr *C.xmlNode) error {
	if C.xmlSecDSigCtxVerify(ctxptr, nodeptr) < C.int(0) {
		return errors.New("failed to verify node")
	}

	if ctxptr.status != C.xmlSecDSigStatusSucceeded {
		return errors.New("signature verification failed")
	}
	return nil
}

func XMLSecDSigCtxVerifyNode(ctx PtrSource, n types.Node) error {
	ctxptr, err := validDSigCtxPtr(ctx)
	if err != nil {
		return err
	}

	nodeptr, err := validNodePtr(n)
	if err != nil {
		return err
	}

	return XMLSecDSigCtxVerifyRaw(ctxptr, nodeptr)
}

func XMLSecDSigCtxVerifyDocument(ctx PtrSource, doc types.Document) error {
	ctxptr, err := validDSigCtxPtr(ctx)
	if err != nil {
		return err
	}

	root, err := doc.DocumentElement()
	if err != nil {
		return err
	}

	rootptr, err := validNodePtr(root)
	if err != nil {
		return err
	}

	cname := stringToXMLChar(SignatureNode)
	cns := stringToXMLChar(DSigNs)
	defer C.free(unsafe.Pointer(cname))
	defer C.free(unsafe.Pointer(cns))

	nodeptr := C.xmlSecFindNode(rootptr, cname, cns)
	if nodeptr == nil {
		return errors.New("failed to find start node")
	}

	return XMLSecDSigCtxVerifyRaw(ctxptr, nodeptr)
}

func XMLSecTmplSignatureCreateNsPref(doc types.Document, c14nMethod TransformID, signMethod TransformID, id string, prefix string) (types.Node, error) {
	docptr := (*C.xmlDoc)(unsafe.Pointer(doc.Pointer()))
	if docptr == nil {
		return nil, clib.ErrInvalidDocument
	}

	var xcid *C.xmlChar
	if id != "" {
		xcid = stringToXMLChar(id)
		defer C.free(unsafe.Pointer(xcid))
	}

	var xcprefix *C.xmlChar
	if prefix != "" {
		xcprefix = stringToXMLChar(prefix)
		defer C.free(unsafe.Pointer(xcprefix))
	}

	ptr := C.xmlSecTmplSignatureCreateNsPref(
		docptr,
		c14nMethod.ptr,
		signMethod.ptr,
		xcid,
		xcprefix,
	)
	if ptr == nil {
		return nil, errors.New("failed to create signature template")
	}

	return dom.WrapNode(uintptr(unsafe.Pointer(ptr)))
}

func XMLSecTmplSignatureAddReference(signode types.Node, digestMethod TransformID, id, uri, nodeType string) (types.Node, error) {
	nptr, err := validNodePtr(signode)
	if err != nil {
		return nil, err
	}

	var idxml, urixml, typexml *C.xmlChar
	if id != "" {
		idxml = stringToXMLChar(id)
		defer C.free(unsafe.Pointer(idxml))
	}
	if uri != "" {
		urixml = stringToXMLChar(uri)
		defer C.free(unsafe.Pointer(urixml))
	}
	if nodeType != "" {
		typexml = stringToXMLChar(nodeType)
		defer C.free(unsafe.Pointer(typexml))
	}

	ptr := C.xmlSecTmplSignatureAddReference(
		nptr,
		digestMethod.ptr,
		idxml,
		urixml,
		typexml,
	)
	if ptr == nil {
		return nil, errors.New("failed to add reference")
	}

	return dom.WrapNode(uintptr(unsafe.Pointer(ptr)))
}

func XMLSecTmplReferenceAddTransform(n types.Node, transformID TransformID) (types.Node, error) {
	nptr, err := validNodePtr(n)
	if err != nil {
		return nil, err
	}

	ptr := C.xmlSecTmplReferenceAddTransform(
		nptr,
		transformID.ptr,
	)
	if ptr == nil {
		return nil, errors.New("failed to add transform")
	}

	return dom.WrapNode(uintptr(unsafe.Pointer(ptr)))
}

func XMLSecTmplSignatureEnsureKeyInfo(n types.Node, id string) (types.Node, error) {
	nptr, err := validNodePtr(n)
	if err != nil {
		return nil, err
	}
	var idc *C.xmlChar
	if id != "" {
		idc = stringToXMLChar(id)
		defer C.free(unsafe.Pointer(idc))
	}

	ret := C.xmlSecTmplSignatureEnsureKeyInfo(nptr, idc)
	if ret == nil {
		return nil, errors.New("failed to add KeyInfo node")
	}

	return dom.WrapNode(uintptr(unsafe.Pointer(ret)))
}

func XMLSecTmplKeyInfoAddX509Data(n types.Node) (types.Node, error) {
	nptr, err := validNodePtr(n)
	if err != nil {
		return nil, err
	}

	ret := C.xmlSecTmplKeyInfoAddX509Data(nptr)
	if ret == nil {
		return nil, errors.New("failed to add X509Data node")
	}

	return dom.WrapNode(uintptr(unsafe.Pointer(ret)))
}

func XMLSecCryptoAppKeyCertLoad(key PtrSource, certFile string, format KeyDataFormat) error {
	keyptr, err := validKeyPtr(key)
	if err != nil {
		return err
	}

	ccert := C.CString(certFile)
	defer C.free(unsafe.Pointer(ccert))

	if C.xmlSecCryptoAppKeyCertLoad(keyptr, ccert, (C.xmlSecKeyDataFormat)(format)) < 0 {
		return errors.New("failed to load cert file")
	}
	return nil
}
