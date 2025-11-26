package crypto

import (
	"golang.org/x/crypto/blake2s"
)

func HashBlake2s256(data ...[]byte) []byte {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// GenerateRandomBytes is already in cipher.go, but we can move it here or keep it there.
// Since cipher.go is in the same package, it's accessible.
