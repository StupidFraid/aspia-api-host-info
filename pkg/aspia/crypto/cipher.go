package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Overhead() int
}

type Decryptor interface {
	Decrypt(ciphertext []byte) ([]byte, error)
	Overhead() int
}

type AeadEncryptor struct {
	aead  cipher.AEAD
	nonce []byte
}

func (e *AeadEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// Standard AEAD format: ciphertext || tag
	DebugLog("[DEBUG ENCRYPT] Nonce: %x, plaintext len: %d", e.nonce, len(plaintext))
	std := e.aead.Seal(nil, e.nonce, plaintext, nil)

	// Aspia format: tag || ciphertext
	// Move tag from end to beginning
	tagSize := e.aead.Overhead()
	ciphertext := make([]byte, len(std))
	copy(ciphertext[0:tagSize], std[len(std)-tagSize:]) // Copy tag to beginning
	copy(ciphertext[tagSize:], std[:len(std)-tagSize])  // Copy ciphertext after tag

	incrementNonce(e.nonce)
	return ciphertext, nil
}

func (e *AeadEncryptor) Overhead() int {
	return e.aead.Overhead()
}

type AeadDecryptor struct {
	aead  cipher.AEAD
	nonce []byte
}

func (d *AeadDecryptor) Overhead() int {
	return d.aead.Overhead()
}

func (d *AeadDecryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// Aspia format: tag || ciphertext
	// Go AEAD expects: ciphertext || tag
	// Rearrange
	tagSize := d.aead.Overhead()
	if len(ciphertext) < tagSize {
		return nil, errors.New("ciphertext too short")
	}

	// Convert from Aspia format to Go format
	std := make([]byte, len(ciphertext))
	copy(std[0:len(ciphertext)-tagSize], ciphertext[tagSize:]) // Copy ciphertext to beginning
	copy(std[len(ciphertext)-tagSize:], ciphertext[0:tagSize]) // Copy tag to end

	DebugLog("[DEBUG DECRYPT] Nonce: %x, std ciphertext len: %d, first bytes: %x", d.nonce, len(std), std[:min(16, len(std))])
	plaintext, err := d.aead.Open(nil, d.nonce, std, nil)
	if err != nil {
		return nil, err
	}
	incrementNonce(d.nonce)
	return plaintext, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func incrementNonce(nonce []byte) {
	// Big-endian increment matching Aspia's large_number_increment.cc
	// Increment from the END of the array (most significant byte last)
	var carry uint32 = 1
	for i := len(nonce) - 1; i >= 0; i-- {
		carry += uint32(nonce[i])
		nonce[i] = byte(carry)
		carry >>= 8
		if carry == 0 {
			break
		}
	}
}

func NewChaCha20Poly1305Encryptor(key, iv []byte) (*AeadEncryptor, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	// IV size for ChaCha20Poly1305 in Go is 12 bytes.
	// Aspia uses 12 bytes IV.
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	return &AeadEncryptor{aead: aead, nonce: nonce}, nil
}

func NewChaCha20Poly1305Decryptor(key, iv []byte) (*AeadDecryptor, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	return &AeadDecryptor{aead: aead, nonce: nonce}, nil
}

func NewAES256GCMEncryptor(key, iv []byte) (*AeadEncryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	return &AeadEncryptor{aead: aead, nonce: nonce}, nil
}

func NewAES256GCMDecryptor(key, iv []byte) (*AeadDecryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	return &AeadDecryptor{aead: aead, nonce: nonce}, nil
}

func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}
