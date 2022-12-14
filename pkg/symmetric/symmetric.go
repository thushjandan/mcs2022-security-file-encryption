package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

const (
	NONCE_BYTES = 12
)

// Transform string based key to a 32 byte fixed size byte array using sha256
func TransformKey(key string) [sha256.Size]byte {
	return sha256.Sum256([]byte(key))
}

func EncryptECB(plainText, key []byte) ([]byte, error) {
	// Load key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := ecb.NewECBEncrypter(block)
	// Add a padding if necessary
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	plainText, err = padder.Pad(plainText)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(plainText))
	// Encrypt
	mode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func DecryptECB(cipherText, key []byte) ([]byte, error) {
	// Load key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := ecb.NewECBDecrypter(block)
	plainText := make([]byte, len(cipherText))
	// Decrypt
	mode.CryptBlocks(plainText, cipherText)
	// Unpad
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	plainText, err = padder.Unpad(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, err
}

func EncrpytCTR(plainText, key []byte) ([]byte, []byte, error) {
	// Load key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	// Generate an IV
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	stream := cipher.NewCTR(block, iv)
	// Encrypt
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	return ciphertext, iv, nil
}

func DecryptCTR(cipherText, key, iv []byte) ([]byte, error) {
	// Load key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(cipherText))
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	stream := cipher.NewCTR(block, iv)
	// Decrypt
	stream.XORKeyStream(plainText, cipherText[aes.BlockSize:])

	return plainText, nil
}

func EncryptGCM(plainText, key []byte) ([]byte, []byte, error) {
	// Load key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, NONCE_BYTES)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt
	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)

	return cipherText, nonce, nil
}

func DecryptGCM(cipherText, key, nonce []byte) ([]byte, error) {
	// Load key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt
	return aesgcm.Open(nil, nonce, cipherText, nil)
}
