package symmetric

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTransformKey(t *testing.T) {
	key := "supersecret"
	want := "f75778f7425be4db0369d09af37a6c2b9a83dea0e53e7bd57412e4b060e607f7"
	hashedKey := TransformKey(key)
	hexEncoded := hex.EncodeToString(hashedKey[:])
	if hexEncoded != want {
		t.Fatalf(`Want: %v --> return value: %v`, want, hexEncoded)
	}
}

func generateKey() [32]byte {
	key := "supersecret"
	hashedKey := TransformKey(key)
	return hashedKey
}

func TestECB(t *testing.T) {
	plainText := []byte("Hello World!")
	key := generateKey()

	cipherText, err := EncryptECB(plainText, key[:])
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	decryptedText, err := DecryptECB(cipherText, key[:])
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	if bytes.Compare(decryptedText, plainText) != 0 {
		t.Fatalf(`Want: %v --> return value: %v`, plainText, decryptedText)
	}

}

func TestCTR(t *testing.T) {
	plainText := []byte("Hello World!")
	key := generateKey()

	cipherText, iv, err := EncrpytCTR(plainText, key[:])
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	decryptedText, err := DecryptCTR(cipherText, key[:], iv)
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	if string(decryptedText[:]) == string(plainText[:]) {
		t.Fatalf(`Want: %v --> return value: %v`, string(plainText[:]), string(decryptedText[:]))
	}

}

func TestGCM(t *testing.T) {
	plainText := []byte("Hello World!")
	key := generateKey()

	cipherText, nonce, err := EncryptGCM(plainText, key[:])
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	decryptedText, err := DecryptGCM(cipherText, key[:], nonce)
	if err != nil {
		t.Fatalf(`Got an error: %v`, err)
	}
	if bytes.Compare(decryptedText, plainText) != 0 {
		t.Fatalf(`Want: %v --> return value: %v`, plainText, decryptedText)
	}

}
