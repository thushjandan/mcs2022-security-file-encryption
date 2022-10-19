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

func TransformKey(key string) [sha256.Size]byte {
	return sha256.Sum256([]byte(key))
}

func EncryptECB(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	plainText, err = padder.Pad(plainText)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(plainText))
	mode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func DecryptECB(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := ecb.NewECBDecrypter(block)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	plainText, err = padder.Unpad(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, err
}

func EncrpytCTR(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	return ciphertext, nil
}

func DecryptCTR(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(cipherText))
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := plainText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plainText, cipherText[aes.BlockSize:])

	return plainText, nil
}

func EncryptGCM(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)

	return cipherText, nil
}

func DecryptGCM(cipherText, key, nonce []byte) ([]byte, error) {
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
