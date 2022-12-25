package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivKey(t *testing.T) {
	privKey := GeneratePrivateKey()

	fmt.Print(privKey.key)
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "19bb3eb99c43514bdad435ebae81e81b86842db9e6b6562805c87210010df88c"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "73b59d6cb4c6290c490c537e7dd9c03c2ce665ee"
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	addess := privKey.Public().Address()
	assert.Equal(t, addressStr, addess.String())
	fmt.Println(addess)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("oi")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	//test with false msg
	assert.False(t, sig.Verify(pubKey, []byte("ola")))

	// test with invalid private key
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
