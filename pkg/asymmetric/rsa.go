package asymmetric

import (
	"crypto/rand"
	"math/big"

	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/symmetric"
)

func EncryptFile(plainText []byte, publicKey *RSAPublicKey) ([]byte, []byte, *big.Int, error) {
	// Generate new symmetric key
	// Generate 256-bit key
	newSymKey := make([]byte, 32)
	_, err := rand.Read(newSymKey)
	// Convert key to bigint
	m := &big.Int{}
	m.SetBytes(newSymKey)
	if err != nil {
		return nil, nil, nil, err
	}
	c := &big.Int{}

	// Encrypt with C = M^e (mod n)
	c.Exp(m, publicKey.E, publicKey.N)
	if err != nil {
		return nil, nil, nil, err
	}
	// Encrypt file with an AEAD cipher
	cipherText, nonce, err := symmetric.EncryptGCM(plainText, newSymKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return cipherText, nonce, c, nil

}

func DecryptFile(cipherText []byte, privateKey *RSAPrivateKey, encryptedSymmetricKey *big.Int, nonce []byte) ([]byte, error) {
	m := decryptSymmetricKey(privateKey, encryptedSymmetricKey)
	plaintext, err := symmetric.DecryptGCM(cipherText, m.Bytes(), nonce)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func decryptSymmetricKey(privateKey *RSAPrivateKey, encryptedSymmetricKey *big.Int) *big.Int {
	m := &big.Int{}
	// Decrypt with M = C^d (mod n)
	m.Exp(encryptedSymmetricKey, privateKey.D, privateKey.N)
	return m
}
