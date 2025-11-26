package crypto

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateX25519KeyPair() (*KeyPair, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (kp *KeyPair) SharedSecret(peerPublicKey []byte) ([]byte, error) {
	return curve25519.X25519(kp.PrivateKey, peerPublicKey)
}
