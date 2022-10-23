package asymmetric

import (
	"bytes"
	"testing"
)

func TestRSAKeyGeneration(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	if privateKey.N.Cmp(publicKey.N) != 0 {
		t.Fatalf(`N not equal in private and public key`)
	}
}

func TestRSA(t *testing.T) {
	plainText := []byte("Hello World!")
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}

	cipherText, nonce, encryptedKey, err := EncryptFile(plainText, publicKey)
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	decryptedText, err := DecryptFile(cipherText, privateKey, encryptedKey, nonce)
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	if bytes.Compare(decryptedText, plainText) != 0 {
		t.Fatalf(`Want: %v --> return value: %v`, plainText, decryptedText)
	}

}
