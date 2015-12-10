/*

Package xmlsec is a Go wrapper for xmlsec1 C library (https://www.aleksey.com/xmlsec/index.html)

In order to use this library, you need xmlsec1, libxml2, libxslt,
and go-libxml2 (https://github.com/lestrrat/go-libxml2)

*/
package xmlsec

import (
	"errors"
	"sync"

	"github.com/lestrrat/go-xmlsec/clib"
)

var initLock = sync.Mutex{}
var initialized bool

// Init calls various initilization functions from xmlsec1. This MUST be
// called prior to doing any real signing/encryption using xmlsec
func Init() error {
	initLock.Lock()
	defer initLock.Unlock()

	if initialized {
		return errors.New("xmlsec already initialized")
	}

	if err := clib.XMLSecInit(); err != nil {
		return err
	}
	initialized = true
	return nil
}

// Shutdown calls various cleanup functions from xmlsec1. This MUST be
// called when you are no longer using xmlsec
func Shutdown() error {
	initLock.Lock()
	defer initLock.Unlock()

	if !initialized {
		return errors.New("xmlsec has not been initialized")
	}
	if err := clib.XMLSecShutdown(); err != nil {
		return err
	}
	initialized = false
	return nil
}
