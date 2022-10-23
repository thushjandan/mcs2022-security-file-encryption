package controller

import (
	"fmt"
	"math/big"
	"os"

	"github.com/thatisuday/commando"
	algoType "github.com/thushjandan/mcs2022-security-file-encryption/pkg/algorithm"
	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/asymmetric"
	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/storage"
	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/symmetric"
)

func SymmetricFileEncryptionAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	key, _ := flags["key"].GetString()
	if key == "default" {
		fmt.Fprintln(os.Stderr, "Please provide an encryption key with flag --key")
		os.Exit(1)
	}
	algorithm, _ := flags["algorithm"].GetString()
	filePath, _ := flags["input"].GetString()
	outputPath, _ := flags["output"].GetString()
	// Check input file
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "Invalid file path.")
		os.Exit(1)
	}
	// Convert user given key to sha256 hash, which has exact 32 bytes
	hashedKey := symmetric.TransformKey(key)
	var err error
	var plainText []byte
	var cipherText []byte
	var nonce []byte
	var encryptionAlgorithm algoType.EncryptionAlgorithm
	if isDecrypt, _ := flags["decrypt"].GetBool(); isDecrypt == true {
		// Decryption
		// Read ciphertext from file
		encryptionAlgorithm, nonce, cipherText, err = storage.GetEncryptedFileContent(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read file to decrypt. Error: %s\n", err.Error())
			os.Exit(1)
			return
		}
		if algorithm == "ecb" {
			// Check if encrypted file has been encrypted using the same algorithm
			if encryptionAlgorithm != algoType.ECB_ALG {
				fmt.Fprintln(os.Stderr, "Input file is not encrypted with ECB. Choose the correct algorithm or do not define one.")
				return
			}
			plainText, err = symmetric.DecryptECB(cipherText, hashedKey[:])
		} else if algorithm == "ctr" {
			// Check if encrypted file has been encrypted using the same algorithm
			if encryptionAlgorithm != algoType.CTR_ALG {
				fmt.Fprintln(os.Stderr, "Input file is not encrypted with CTR. Choose the correct algorithm or do not define one.")
				return
			}
			plainText, err = symmetric.DecryptCTR(cipherText, hashedKey[:], nonce)
		} else if algorithm == "gcm" {
			// Check if encrypted file has been encrypted using the same algorithm
			if encryptionAlgorithm != algoType.GCM_ALG {
				fmt.Fprintln(os.Stderr, "Input file is not encrypted with ECB. Choose the correct algorithm or do not define one.")
				return
			}
			plainText, err = symmetric.DecryptGCM(cipherText, hashedKey[:], nonce)
		} else {
			fmt.Fprintln(os.Stderr, "Invalid algorithm given.")
			return
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Decryption failed.\n %s", err.Error())
			os.Exit(1)
			return
		}

		// Write decrypted file to the output file.
		err = os.WriteFile(outputPath, plainText, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write decrypted file. Error: %s\n", err.Error())
			os.Exit(1)
			return
		}

	} else {
		// Encryption
		encryptionAlgorithm := algoType.INVALID_ALG
		// Read plaintext file
		plainText, err = storage.GetFileContent(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read file to encrypt. Error: %s\n", err)
			return
		}
		// Encrypt plaintext
		if algorithm == "ecb" {
			encryptionAlgorithm = algoType.ECB_ALG
			cipherText, err = symmetric.EncryptECB(plainText, hashedKey[:])
		} else if algorithm == "ctr" {
			encryptionAlgorithm = algoType.CTR_ALG
			cipherText, nonce, err = symmetric.EncrpytCTR(plainText, hashedKey[:])
		} else if algorithm == "gcm" {
			encryptionAlgorithm = algoType.GCM_ALG
			cipherText, nonce, err = symmetric.EncryptGCM(plainText, hashedKey[:])
		} else {
			fmt.Fprintf(os.Stderr, "Invalid algorithm given.")
			return
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Decryption failed.\n %s", err)
			return
		}
		// Write encrypted content to ouput file
		err = storage.WriteEncryptedFile(outputPath, encryptionAlgorithm, nonce, cipherText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write encrypted file. Error: %s\n", err)
			return
		}

	}
}

func AsymmetricFileEncryptionAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	privateKeyPath, _ := flags["private"].GetString()
	publicKeyPath, _ := flags["public"].GetString()
	inputFilePath, _ := flags["input"].GetString()
	outputFilePath, _ := flags["output"].GetString()
	if isDecrypt, _ := flags["decrypt"].GetBool(); isDecrypt == true {
		// Decrypt
		// Load private key
		privateKey, err := storage.LoadRSAPrivateKey(privateKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load private key from file. Error %s\n", err)
			return
		}
		// Load encrypted file
		encryptedContent, err := storage.ReadRSAEncryptedFile(inputFilePath)
		// Convert private key to bigInt
		encryptedKey := &big.Int{}
		encryptedKey.SetBytes(encryptedContent.EncryptedKey)
		plainText, err := asymmetric.DecryptFile(encryptedContent.EncryptedContent, privateKey, encryptedKey, encryptedContent.Nonce)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot decrypt file. Error %s\n", err)
			return
		}
		// Write decrypted file to output file
		err = os.WriteFile(outputFilePath, plainText, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write decrypted file. Error %s\n", err)
			return
		}

	} else {
		// Encrypt
		// Load public key
		publicKey, err := storage.LoadRSAPublicKey(publicKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load public key from file. Error %s\n", err)
			return
		}
		plainText, err := storage.GetFileContent(inputFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read file to decrypt. Error: %s\n", err)
			return
		}
		cipherText, nonce, encryptedKey, err := asymmetric.EncryptFile(plainText, publicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot encrypt file. Error: %s\n", err)
			return
		}
		// Store encrypted content as GOB serialized file.
		payload := &storage.GobRSAEncrypted{
			EncryptedContent: cipherText,
			EncryptedKey:     encryptedKey.Bytes(),
			Nonce:            nonce,
		}
		err = storage.WriteRSAEncryptedFile(outputFilePath, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write file. Error: %s\n", err)
			return
		}
	}

}

func GenerateKeyAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	fileName, _ := flags["name"].GetString()
	keySize, _ := flags["bits"].GetInt()
	privateKey, publicKey, err := asymmetric.GenerateKey(keySize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot generate a new key pair. Error %s\n", err)
		return
	}
	// Convert BigInt to byte array
	marshalledD, err := privateKey.D.MarshalText()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	marshalledN, err := privateKey.N.MarshalText()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	// add a delimiter between D and N
	marshalledD = append(marshalledD, '.')
	transformedPrivateKey := append(marshalledD, marshalledN...)
	marshalledE, err := publicKey.E.MarshalText()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	marshalledN, err = publicKey.N.MarshalText()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	// Add a delimiter between E and N
	marshalledE = append(marshalledE, '.')
	transformedPublicKey := append(marshalledE, marshalledN...)
	err = os.WriteFile(fileName+".key", transformedPrivateKey, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write private key to file. Error %s\n", err)
		return
	}
	err = os.WriteFile(fileName+".pub", transformedPublicKey, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write public key to file. Error %s\n", err)
		return
	}
}
