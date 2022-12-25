package crypto

//imports necessary tools
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// declare the length of the private key, public key and the seed
const (
	privKeyLen = 64
	pubKeyLen  = 32
	seedLen    = 32
	addressLen = 20
)

// generates the 'class' wich defines the private key
type PrivateKey struct {
	key ed25519.PrivateKey
}

// decodes the string into bytes ans returns the NewPrivateKeyFromSeed func
func NewPrivateKeyFromString(s string) *PrivateKey {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return NewPrivateKeyFromSeed(b)
}

// takes a slice of bytes as seed and creates private key from it, returning the struct PrivateKey
func NewPrivateKeyFromSeed(seed []byte) *PrivateKey {
	if len(seed) != seedLen {
		panic("invalid seed length, must be 32")
	}

	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

// the main idea of this function is to return the PrivateKey struct
// it makes a slice of bytes with the length of the seed (32 bytes) and returns the PrivateKey struct with the private key as key.
// OBS: a private key is basically a slice of 64 bytes
func GeneratePrivateKey() *PrivateKey {

	// seed receives a slice of bytes with the seedLen length
	seed := make([]byte, seedLen)

	// copies a random number into the seed
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

// return the key from PrivateKey struct
func (p *PrivateKey) Bytes() []byte {
	return p.key
}

// signs a message using the private key and returns a Signature struct with the message signed
func (p *PrivateKey) Sign(msg []byte) *Signature {
	return &Signature{
		value: ed25519.Sign(p.key, msg),
	}
}

// this method creates a slice of bytes called b with the length of the public key (32 bytes)
// after this it copies the last 32 bytes of the private key into the slice b
// finally it returns a new Public key struct
func (p *PrivateKey) Public() *PublicKey {
	b := make([]byte, pubKeyLen)
	copy(b, p.key[32:])

	return &PublicKey{
		key: b,
	}
}

// struct of the public key
type PublicKey struct {
	key ed25519.PublicKey
}

// returns the public key address like this: p.key[len(p.key)-addressLen:]
func (p *PublicKey) Address() Address {
	return Address{
		value: p.key[len(p.key)-addressLen:],
	}
}

// returns the public key
func (p *PublicKey) Bytes() []byte {
	return p.key
}

// struct which is able to contain the value of the message signed
type Signature struct {
	value []byte
}

// returns the message signed
func (s *Signature) Bytes() []byte {
	return s.value
}

func (s *Signature) Verify(pubKey *PublicKey, msg []byte) bool {
	return ed25519.Verify(pubKey.key, msg, s.value)
}

type Address struct {
	value []byte
}

func (a Address) Bytes() []byte {
	return a.value
}

func (a Address) String() string {
	return hex.EncodeToString(a.value)
}
