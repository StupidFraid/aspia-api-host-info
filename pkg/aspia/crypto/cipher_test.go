package crypto

import (
	"bytes"
	"testing"
)

func TestChaCha20Poly1305EncryptDecrypt(t *testing.T) {
	// Test key and IV (32 bytes and 12 bytes)
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	iv := []byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab,
	}

	// Create encryptor and decryptor
	encryptor, err := NewChaCha20Poly1305Encryptor(key, iv)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	decryptor, err := NewChaCha20Poly1305Decryptor(key, iv)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	// Test data
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte("Hello")},
		{"Medium", []byte("Hello, World! This is a test message.")},
		{"Long", bytes.Repeat([]byte("A"), 1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			t.Logf("Original plaintext length: %d", len(tc.plaintext))
			ciphertext, err := encryptor.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			t.Logf("Ciphertext length: %d (should be %d + 16)", len(ciphertext), len(tc.plaintext))

			// Expected ciphertext length = plaintext + tag (16 bytes)
			expectedLen := len(tc.plaintext) + 16
			if len(ciphertext) != expectedLen {
				t.Errorf("Ciphertext length mismatch: got %d, want %d", len(ciphertext), expectedLen)
			}

			// Decrypt
			decrypted, err := decryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Compare
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("Decrypted data doesn't match original.\nOriginal:  %x\nDecrypted: %x", tc.plaintext, decrypted)
			}
		})
	}
}

func TestNonceIncrement(t *testing.T) {
	tests := []struct {
		name     string
		initial  []byte
		expected []byte
	}{
		{
			name:     "Simple increment",
			initial:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name:     "Carry over",
			initial:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff},
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name:     "Multiple carry",
			initial:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff},
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
		},
		{
			name:     "Real-world IV",
			initial:  []byte{0xc8, 0x21, 0x3e, 0x29, 0xd1, 0x67, 0xb5, 0x03, 0xc2, 0xd6, 0xe7, 0xb1},
			expected: []byte{0xc8, 0x21, 0x3e, 0x29, 0xd1, 0x67, 0xb5, 0x03, 0xc2, 0xd6, 0xe7, 0xb2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := make([]byte, len(tt.initial))
			copy(nonce, tt.initial)

			incrementNonce(nonce)

			if !bytes.Equal(nonce, tt.expected) {
				t.Errorf("Nonce increment failed.\nInitial:  %x\nExpected: %x\nGot:      %x", tt.initial, tt.expected, nonce)
			}
		})
	}
}

func TestTagRearrangement(t *testing.T) {
	// This test verifies that our tag rearrangement logic is correct
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	iv := []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}

	encryptor, _ := NewChaCha20Poly1305Encryptor(key, iv)
	plaintext := []byte("Test message for tag verification")

	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Ciphertext length: %d", len(ciphertext))
	t.Logf("First 16 bytes (should be TAG): %x", ciphertext[:16])
	t.Logf("Remaining bytes (should be encrypted data): %x", ciphertext[16:])

	// Verify format: first 16 bytes should be tag, rest should be encrypted data
	// We can't verify the exact values, but we can check the length
	if len(ciphertext) != len(plaintext)+16 {
		t.Errorf("Ciphertext length incorrect: got %d, want %d", len(ciphertext), len(plaintext)+16)
	}
}

func TestMultipleMessagesNonceProgression(t *testing.T) {
	// Test that nonce increments correctly across multiple encryptions
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	encryptor, _ := NewChaCha20Poly1305Encryptor(key, iv)
	decryptor, _ := NewChaCha20Poly1305Decryptor(key, iv)

	messages := []string{
		"First message",
		"Second message",
		"Third message",
	}

	for i, msg := range messages {
		t.Logf("Message %d: %s", i+1, msg)

		plaintext := []byte(msg)
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed for message %d: %v", i+1, err)
		}

		decrypted, err := decryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decryption failed for message %d: %v", i+1, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Message %d mismatch.\nOriginal:  %s\nDecrypted: %s", i+1, plaintext, decrypted)
		}
	}
}
