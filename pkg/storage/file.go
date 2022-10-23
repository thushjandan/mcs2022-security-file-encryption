package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"math/big"
	"os"

	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/algorithm"
	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/asymmetric"
)

type GobRSAEncrypted struct {
	EncryptedContent []byte
	Nonce            []byte
	EncryptedKey     []byte
}

func GetFileContent(path string) ([]byte, error) {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

// Read symmetric encrypted file
// 1 byte (uint8) for algorithm type
// 8 byte for nonce length int64
// x byte for nonce
// rest of the file contains the encrypted payload
func GetEncryptedFileContent(path string) (algorithm.EncryptionAlgorithm, []byte, []byte, error) {
	fp, err := os.Open(path)
	defer fp.Close()

	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}
	// Read header => algorithm type and nonce size
	buf := make([]byte, 9)
	readCount, err := fp.ReadAt(buf, 0)
	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}
	if readCount != 9 {
		return algorithm.INVALID_ALG, nil, nil, errors.New("Invalid encrypted file. Cannot read header.")
	}
	bufReader := bytes.NewReader(buf)
	var rEncryptionAlgorithm uint8
	var rNonceLength int64
	var nonce []byte
	// Read algorithm type from file
	binary.Read(bufReader, binary.LittleEndian, &rEncryptionAlgorithm)
	// validate the algorithm type
	if rEncryptionAlgorithm < 1 || rEncryptionAlgorithm > 4 {
		return algorithm.INVALID_ALG, nil, nil, errors.New("Invalid encrypted file. Invalid encryption algorithm type.")
	}
	// Read nonce size
	binary.Read(bufReader, binary.LittleEndian, &rNonceLength)
	// if nonce length bigger than 0, then we have to read the nonce value from file
	if rNonceLength > 0 {
		// Read nonce value
		nonce = make([]byte, rNonceLength)
		readCount, err = fp.ReadAt(nonce, 9)
		if err != nil {
			return algorithm.INVALID_ALG, nil, nil, err
		}
	}

	// Get total file size
	fi, err := os.Stat(path)
	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}
	// Read the encrypted payload
	data := make([]byte, fi.Size()-(int64(rNonceLength)+9))
	readCount, err = fp.ReadAt(data, int64(rNonceLength)+9)
	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}

	return algorithm.EncryptionAlgorithm(rEncryptionAlgorithm), nonce, data, nil
}

func WriteEncryptedFile(path string, encalg algorithm.EncryptionAlgorithm, nonce, data []byte) error {
	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	defer fp.Close()

	if err != nil {
		return err
	}
	// prepare file header
	buf := new(bytes.Buffer)
	nonceLength := int64(len(nonce))
	binary.Write(buf, binary.LittleEndian, encalg)
	binary.Write(buf, binary.LittleEndian, nonceLength)
	if nonce != nil {
		binary.Write(buf, binary.LittleEndian, nonce)
	}
	offset := len(nonce) + 9

	// int = 8 bytes + 1 byte
	err = fp.Truncate(int64(len(data) + offset))
	if err != nil {
		return err
	}

	// Write file header
	_, err = fp.WriteAt(buf.Bytes(), 0)
	if err != nil {
		return err
	}
	// Write cipher text
	_, err = fp.WriteAt(data, int64(offset))
	if err != nil {
		return err
	}
	return nil

}

// Read a RSA key from file
func loadRSAKey(filepath string) ([][]byte, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	splittedContent := bytes.Split(content, []byte("."))
	return splittedContent, nil
}

func LoadRSAPublicKey(filepath string) (*asymmetric.RSAPublicKey, error) {
	splittedContent, err := loadRSAKey(filepath)
	if err != nil {
		return nil, err
	}
	publicKey := &asymmetric.RSAPublicKey{
		E: &big.Int{},
		N: &big.Int{},
	}

	// Transform byte array back to BigInt
	err = publicKey.E.UnmarshalText(splittedContent[0])
	if err != nil {
		return nil, err
	}

	err = publicKey.N.UnmarshalText(splittedContent[1])
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func LoadRSAPrivateKey(filepath string) (*asymmetric.RSAPrivateKey, error) {
	splittedContent, err := loadRSAKey(filepath)
	if err != nil {
		return nil, err
	}

	privateKey := &asymmetric.RSAPrivateKey{
		D: &big.Int{},
		N: &big.Int{},
	}

	// Transform byte array back to BigInt
	err = privateKey.D.UnmarshalText(splittedContent[0])
	if err != nil {
		return nil, err
	}

	err = privateKey.N.UnmarshalText(splittedContent[1])
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Serizalize a encrypted payload as GOB
func WriteRSAEncryptedFile(filepath string, data *GobRSAEncrypted) error {
	var writeBuffer bytes.Buffer
	fileEncoder := gob.NewEncoder(&writeBuffer)
	err := fileEncoder.Encode(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath, writeBuffer.Bytes(), 0644)
	if err != nil {
		return err
	}
	return nil
}

// Deserialize a RSA encrypted file, which is in GOB format
func ReadRSAEncryptedFile(filepath string) (*GobRSAEncrypted, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(data)
	fileDecoder := gob.NewDecoder(reader)
	var gobData GobRSAEncrypted
	err = fileDecoder.Decode(&gobData)
	if err != nil {
		return nil, err
	}
	return &gobData, nil
}
