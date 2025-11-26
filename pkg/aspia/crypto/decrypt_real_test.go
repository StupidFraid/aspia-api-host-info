package crypto

import (
	"encoding/hex"
	"testing"
)

func TestDecryptRealSessionChallenge(t *testing.T) {
	//  Real data from packet capture
	sessionKeyHex := "5112e5386f0b39fa06212e47eee59b7585b7fe9c9d6314361f0b7431c7e80860"
	decryptIvHex := "16e8110cd4b469e93daba54e"
	ciphertextHex := "37c56e709d3e0022d787750815bfc515167be6be2c1cd21ea93547a874bd913176beb770eed32e67691d541d2122444904bfdbf33137a8"

	sessionKey, _ := hex.DecodeString(sessionKeyHex)
	decryptIv, _ := hex.DecodeString(decryptIvHex)
	ciphertext, _ := hex.DecodeString(ciphertextHex)

	t.Logf("Session key: %x (%d bytes)", sessionKey, len(sessionKey))
	t.Logf("Decrypt IV: %x (%d bytes)", decryptIv, len(decryptIv))
	t.Logf("Ciphertext: %x (%d bytes)", ciphertext, len(ciphertext))

	// Create decryptor
	decryptor, err := NewChaCha20Poly1305Decryptor(sessionKey, decryptIv)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	// Try to decrypt
	plaintext, err := decryptor.Decrypt(ciphertext)
	if err != nil {
		t.Logf("Decryption failed (expected): %v", err)

		// Try WITHOUT tag rearrangement (maybe server sends in standard format?)
		t.Log("Trying standard format (ciphertext || tag)...")
		decryptor2, _ := NewChaCha20Poly1305Decryptor(sessionKey, decryptIv)

		// Don't rearrange, use as-is
		aead := decryptor2.aead
		plaintext2, err2 := aead.Open(nil, decryptIv, ciphertext, nil)
		if err2 != nil {
			t.Logf("Standard format also failed: %v", err2)
		} else {
			t.Logf("SUCCESS with standard format! Plaintext: %x", plaintext2)
		}
	} else {
		t.Logf("SUCCESS! Plaintext: %x", plaintext)
		t.Logf("Plaintext string: %s", string(plaintext))
	}
}
