package xmlsec

import (
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
	ctx, err := NewDSigCtx()
	if !assert.NoError(t, err, "NewDSigCtx should succeed") {
		return
	}
	defer ctx.Free()
}