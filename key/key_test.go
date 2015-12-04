package key

import (
	"crypto/dsa"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDSA(t *testing.T) {
	params := dsa.Parameters{}
	if !assert.NoError(t, dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256), "Parameter generation succeeds") {
		return
	}

	privkey := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: params,
		},
	}

	if !assert.NoError(t, dsa.GenerateKey(&privkey, rand.Reader), "GenerateKey succeeds") {
		return
	}

	key := NewDSA(&privkey.PublicKey)
	xmlstr, err := key.Serialize()
	if !assert.NoError(t, err, "Serialize succeeds") {
		return
	}

	t.Logf("%s", xmlstr)
}