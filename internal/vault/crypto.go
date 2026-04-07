package vault

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
)

func generateIdentityFile() (*age.HybridIdentity, []byte, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, nil, err
	}
	contents := fmt.Appendf(nil, "# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), identity.Recipient(), identity.String())
	return identity, contents, nil
}

func parseIdentityFile(contents []byte) (*age.HybridIdentity, error) {
	identities, err := age.ParseIdentities(bytes.NewReader(contents))
	if err != nil {
		return nil, err
	}
	if len(identities) != 1 {
		return nil, fmt.Errorf("expected one identity, found %d", len(identities))
	}
	identity, ok := identities[0].(*age.HybridIdentity)
	if !ok {
		return nil, fmt.Errorf("identity file does not contain a post-quantum age identity")
	}
	return identity, nil
}

func MarshalIdentity(identity *age.HybridIdentity) []byte {
	return append([]byte(identity.String()), '\n')
}

func ParseIdentity(contents []byte) (*age.HybridIdentity, error) {
	return parseIdentityFile(contents)
}

func encryptWithRecipient(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encryptWithPassphrase(plaintext, password []byte, workFactor int) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(string(password))
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(workFactor)
	return encryptWithRecipient(plaintext, recipient)
}

func decryptWithPassphrase(ciphertext, password []byte) ([]byte, error) {
	identity, err := age.NewScryptIdentity(string(password))
	if err != nil {
		return nil, err
	}
	return decryptWithIdentity(ciphertext, identity)
}

func decryptWithIdentity(ciphertext []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func redactRecipient(recipient string) string {
	if len(recipient) <= 24 {
		return recipient
	}
	return recipient[:12] + "..." + recipient[len(recipient)-12:]
}

func isIncorrectPassphrase(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "incorrect passphrase")
}
