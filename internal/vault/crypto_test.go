package vault

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func TestDecryptDiscardsPlaintextWhenAuthenticationFails(t *testing.T) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Multiple payload chunks ensure the decryptor has returned plaintext
	// before it discovers the corrupted final chunk.
	plaintext := bytes.Repeat([]byte("secret"), 32*1024)
	ciphertext, err := encryptWithRecipient(plaintext, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	decrypted, err := decryptWithIdentity(ciphertext, identity)
	if err == nil {
		t.Fatal("expected authentication failure")
	}
	if decrypted != nil {
		t.Fatal("decryption returned partial plaintext after authentication failure")
	}
}
