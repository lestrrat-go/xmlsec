/*
Package xmlsec is a Go binding for XML Security Library (https://www.aleksey.com/xmlsec/index.html)

In order to use this library, you need go-libxml2 (https://github.com/lestrrat/go-libxml2)
*/

package xmlsec

/*
#cgo pkg-config: xmlsec1
#include <stdlib.h>
#include <libxml/tree.h>
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

*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/lestrrat/go-libxml2"
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

func Init() error {
	if C.go_xmlsec_init() < C.int(0) {
		return errors.New("failed to initialize")
	}
	return nil
}

func Shutdown() error {
	C.go_xmlsec_shutdown()
	return nil
}

func xmlCharToString(s *C.xmlChar) string {
	return C.GoString(C.to_charptr(s))
}

func stringToXmlChar(s string) *C.xmlChar {
	return C.to_xmlcharptr(C.CString(s))
}

func xmlSecDSigCtxCreate() (*DSigCtx, error) {
	ctx := C.xmlSecDSigCtxCreate(nil)
	if ctx == nil {
		return nil, errors.New("failed to create DSigCtx")
	}
	return &DSigCtx{ptr: ctx}, nil
}

func xmlSecDSigCtxDestroy(ctx *DSigCtx) error {
	ptr := ctx.ptr
	if ptr == nil {
		return ErrInvalidDSigCtx
	}

	C.xmlSecDSigCtxDestroy(ptr)
	return nil
}

func xmlSecCryptoAppKeyLoadMemory(buf []byte, format KeyDataFormat) (*Key, error) {
	key := C.xmlSecCryptoAppKeyLoadMemory(
		(*C.xmlSecByte)(unsafe.Pointer(&buf[0])),
		(C.xmlSecSize)(C.int(len(buf))),
		(C.xmlSecKeyDataFormat)(format),
		nil,
		nil,
		nil,
	)
	if key == nil {
		return nil, errors.New("failed to load key")
	}
	return &Key{ptr: key}, nil
}

func xmlSecCryptoAppKeyLoad(file string, format KeyDataFormat) (*Key, error) {
	key := C.xmlSecCryptoAppKeyLoad(C.CString(file), (C.xmlSecKeyDataFormat)(format), nil, nil, nil)
	if key == nil {
		return nil, errors.New("failed to load key")
	}

	if C.xmlSecKeySetName(key, stringToXmlChar(file)) < C.int(0) {
		return nil, errors.New("failed to set key name")
	}

	return &Key{ptr: key}, nil
}

func (d *DSigCtx) SetKey(key *Key) error {
	ptr := d.ptr
	if ptr == nil {
		return ErrInvalidDSigCtx
	}

	ptr.signKey = key.ptr
	return nil
}

func xmlSecDSigCtxSignRaw(ctxptr *C.xmlSecDSigCtx, nodeptr *C.xmlNode) error {
	if C.xmlSecDSigCtxSign(ctxptr, nodeptr) < C.int(0) {
		return errors.New("failed to sign node")
	}
	return nil
}

func xmlSecDSigCtxSignNode(ctx *DSigCtx, n libxml2.Node) error {
	nodeptr := (*C.xmlNode)(n.Pointer())
	if nodeptr == nil {
		return libxml2.ErrInvalidNode
	}

	ctxptr := ctx.ptr
	if ctxptr == nil {
		return ErrInvalidDSigCtx
	}
	return xmlSecDSigCtxSignRaw(ctxptr, nodeptr)
}

func xmlSecDSigCtxSignDocument(ctx *DSigCtx, doc *libxml2.Document) error {
	root, err := doc.DocumentElement()
	if err != nil {
		return err
	}

	rootptr := (*C.xmlNode)(unsafe.Pointer(root.Pointer()))
	if rootptr == nil {
		return libxml2.ErrNodeNotFound
	}

	nodeptr := C.xmlSecFindNode(
		rootptr,
		stringToXmlChar(SignatureNode),
		stringToXmlChar(DSigNs),
	)

	if nodeptr == nil {
		return errors.New("failed to find start node")
	}

	ctxptr := ctx.ptr
	if ctxptr == nil {
		return ErrInvalidDSigCtx
	}

	return xmlSecDSigCtxSignRaw(ctxptr, nodeptr)
}

func xmlSecDSigCtxVerifyRaw(ctxptr *C.xmlSecDSigCtx, nodeptr *C.xmlNode) error {
	if C.xmlSecDSigCtxVerify(ctxptr, nodeptr) < C.int(0) {
		return errors.New("failed to verify node")
	}

	if ctxptr.status != C.xmlSecDSigStatusSucceeded {
		return errors.New("signature verification failed")
	}
	return nil
}

func xmlSecDSigCtxVerifyNode(ctx *DSigCtx, n libxml2.Node) error {
	nodeptr := (*C.xmlNode)(n.Pointer())
	if nodeptr == nil {
		return libxml2.ErrInvalidNode
	}

	ctxptr := ctx.ptr
	if ctxptr == nil {
		return ErrInvalidDSigCtx
	}
	return xmlSecDSigCtxVerifyRaw(ctxptr, nodeptr)
}

func xmlSecDSigCtxVerifyDocument(ctx *DSigCtx, doc *libxml2.Document) error {
	root, err := doc.DocumentElement()
	if err != nil {
		return err
	}

	rootptr := (*C.xmlNode)(unsafe.Pointer(root.Pointer()))
	if rootptr == nil {
		return libxml2.ErrNodeNotFound
	}

	nodeptr := C.xmlSecFindNode(
		rootptr,
		stringToXmlChar(SignatureNode),
		stringToXmlChar(DSigNs),
	)
	if nodeptr == nil {
		return errors.New("failed to find start node")
	}

	ctxptr := ctx.ptr
	if ctxptr == nil {
		return ErrInvalidDSigCtx
	}
	return xmlSecDSigCtxVerifyRaw(ctxptr, nodeptr)
}

func xmlSecTmplSignatureCreate(doc *libxml2.Document, c14nMethod TransformID, signMethod TransformID, id string) (libxml2.Node, error) {
	docptr := (*C.xmlDoc)(doc.Pointer())
	if docptr == nil {
		return nil, libxml2.ErrInvalidDocument
	}

	var idxml *C.xmlChar
	if id != "" {
		idxml = stringToXmlChar(id)
	}
	ptr := C.xmlSecTmplSignatureCreate(
		docptr,
		c14nMethod.ptr,
		signMethod.ptr,
		idxml,
	)
	if ptr == nil {
		return nil, errors.New("failed to create signature template")
	}

	return libxml2.WrapToNodeUnsafe(unsafe.Pointer(ptr))
}

func xmlSecTmplSignatureAddReference(signode libxml2.Node, digestMethod TransformID, id, uri, nodeType string) (libxml2.Node, error) {
	nptr := (*C.xmlNode)(signode.Pointer())
	if nptr == nil {
		return nil, libxml2.ErrInvalidNode
	}

	var idxml, urixml, typexml *C.xmlChar
	if id != "" {
		idxml = stringToXmlChar(id)
	}
	if uri != "" {
		urixml = stringToXmlChar(uri)
	}
	if nodeType != "" {
		typexml = stringToXmlChar(nodeType)
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

	return libxml2.WrapToNodeUnsafe(unsafe.Pointer(ptr))
}

func xmlSecTmplReferenceAddTransform(n libxml2.Node, transformId TransformID) (libxml2.Node, error) {
	nptr := (*C.xmlNode)(n.Pointer())
	if nptr == nil {
		return nil, libxml2.ErrInvalidNode
	}

	ptr := C.xmlSecTmplReferenceAddTransform(
		nptr,
		transformId.ptr,
	)
	if ptr == nil {
		return nil, errors.New("failed to add transform")
	}

	return libxml2.WrapToNodeUnsafe(unsafe.Pointer(ptr))
}
