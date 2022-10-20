package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"

	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/algorithm"
)

func GetFileContent(path string) ([]byte, error) {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

func GetEncryptedFileContent(path string) (algorithm.EncryptionAlgorithm, []byte, []byte, error) {
	fp, err := os.Open(path)
	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}
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
	binary.Read(bufReader, binary.LittleEndian, &rEncryptionAlgorithm)
	if rEncryptionAlgorithm < 1 || rEncryptionAlgorithm > 4 {
		return algorithm.INVALID_ALG, nil, nil, errors.New("Invalid encrypted file. Invalid encryption algorithm type.")
	}
	binary.Read(bufReader, binary.LittleEndian, &rNonceLength)
	if rNonceLength > 0 {
		nonce = make([]byte, rNonceLength)
		readCount, err = fp.ReadAt(nonce, 9)
		if err != nil {
			return algorithm.INVALID_ALG, nil, nil, err
		}
	}

	fi, err := os.Stat(path)
	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}
	data := make([]byte, fi.Size()-(int64(rNonceLength)+9))
	readCount, err = fp.ReadAt(data, int64(rNonceLength)+9)
	if err != nil {
		return algorithm.INVALID_ALG, nil, nil, err
	}

	return algorithm.EncryptionAlgorithm(rEncryptionAlgorithm), nonce, data, nil
}

func WriteEncryptedFile(path string, encalg algorithm.EncryptionAlgorithm, nonce, data []byte) error {
	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
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

	_, err = fp.WriteAt(buf.Bytes(), 0)
	if err != nil {
		return err
	}
	_, err = fp.WriteAt(data, int64(offset))
	if err != nil {
		return err
	}
	return nil

}
