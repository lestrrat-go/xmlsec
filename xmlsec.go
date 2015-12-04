/*

Package xmlsec is a Go wrapper for xmlsec1 C library (https://www.aleksey.com/xmlsec/index.html)

In order to use this library, you need xmlsec1, libxml2, libxslt,
and go-libxml2 (https://github.com/lestrrat/go-libxml2)

*/
package xmlsec

import (
	"github.com/lestrrat/go-xmlsec/clib"
)

// Init calls various initilization functions from xmlsec1
func Init() error {
	return clib.XMLSecInit()
}

// Shutdown calls various cleanup functions from xmlsec1
func Shutdown() error {
	return clib.XMLSecShutdown()
}

