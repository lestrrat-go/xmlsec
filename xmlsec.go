package xmlsec

import (
	"github.com/lestrrat/go-xmlsec/clib"
)

func Init() error {
	return clib.XMLSecInit()
}

func Shutdown() error {
	return clib.XMLSecShutdown()
}

