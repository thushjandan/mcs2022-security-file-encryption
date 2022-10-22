package main

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

func main() {
	commando.
		SetExecutableName("fenc").
		SetVersion("v1.0.0").
		SetDescription("This CLI tool helps you encrypt and decrypt files with several symmetric and text book RSA encryption algorithm.")

	commando.Register("sym").
		SetShortDescription("file encryption using symmetric algorithms").
		AddFlag("algorithm,a", "symmetric algortihm to choose", commando.String, "gcm").
		AddFlag("decrypt,d", "decrypt or encrypt. If flag is set, then file will be decrypted. Otherwise file will be encrypted", commando.Bool, false).
		AddFlag("key,k", "passphrase used as key", commando.String, "default").
		AddFlag("input,i", "input file", commando.String, "./myFile").
		AddFlag("output,o", "output file", commando.String, "./myFile.output").
		SetAction(symmetricFileEncryptionAction)

	commando.Register("asym").
		SetShortDescription("file encryption using asymmetric algortihm").
		AddFlag("algorithm,a", "asymmetric algorthm to choose", commando.String, "rsa").
		AddFlag("decrypt,d", "decrypt or encrypt. If flag is set, then file will be decrypted. Otherwise file will be encrypted", commando.Bool, false).
		AddFlag("private,k", "private key", commando.String, "./myKey.key").
		AddFlag("public,p", "private key", commando.String, "./myKey.pub").
		AddFlag("input,i", "input file", commando.String, "./myFile").
		AddFlag("output,o", "output file", commando.String, "./myFile.output").
		SetAction(asymmetricFileEncryptionAction)
	commando.Register("generate").
		SetShortDescription("Generates private public key pair").
		AddFlag("name,n", "file name of newly generates key pairs", commando.String, "myKey").
		SetAction(generateKeyAction)
	commando.Parse(nil)

}

func symmetricFileEncryptionAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	key, _ := flags["key"].GetString()
	if key == "default" {
		fmt.Println("Please provide an encryption key with flag --key")
		os.Exit(1)
	}
	algorithm, _ := flags["algorithm"].GetString()
	filePath, _ := flags["input"].GetString()
	outputPath, _ := flags["output"].GetString()
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Println("Invalid file path.")
		os.Exit(1)
	}
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
			fmt.Printf("Cannot read file to decrypt. Error: %s\n", err.Error())
			os.Exit(1)
			return
		}
		if algorithm == "ecb" {
			if encryptionAlgorithm != algoType.ECB_ALG {
				fmt.Println("Input file is not encrypted with ECB. Choose the correct algorithm or do not define one.")
				return
			}
			plainText, err = symmetric.DecryptECB(cipherText, hashedKey[:])
		} else if algorithm == "ctr" {
			if encryptionAlgorithm != algoType.CTR_ALG {
				fmt.Println("Input file is not encrypted with CTR. Choose the correct algorithm or do not define one.")
				return
			}
			plainText, err = symmetric.DecryptCTR(cipherText, hashedKey[:], nonce)
		} else if algorithm == "gcm" {
			if encryptionAlgorithm != algoType.GCM_ALG {
				fmt.Println("Input file is not encrypted with ECB. Choose the correct algorithm or do not define one.")
				return
			}
			plainText, err = symmetric.DecryptGCM(cipherText, hashedKey[:], nonce)
		} else {
			fmt.Println("Invalid algorithm given.")
			return
		}
		if err != nil {
			fmt.Printf("Decryption failed.\n %s", err.Error())
			os.Exit(1)
			return
		}
		err = os.WriteFile(outputPath, plainText, 0644)

	} else {
		// Encryption
		encryptionAlgorithm := algoType.INVALID_ALG
		plainText, err = storage.GetFileContent(filePath)
		if err != nil {
			fmt.Printf("Cannot read file to decrypt. Error: %s\n", err)
			return
		}
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
			fmt.Println("Invalid algorithm given.")
			return
		}

		if err != nil {
			fmt.Printf("Decryption failed.\n %s", err)
			return
		}
		//err = os.WriteFile(outputPath, cipherText, 0644)
		err = storage.WriteEncryptedFile(outputPath, encryptionAlgorithm, nonce, cipherText)
		if err != nil {
			fmt.Printf("Cannot write encrypted file. Error: %s\n", err)
			return
		}

	}
}

func asymmetricFileEncryptionAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	privateKeyPath, _ := flags["private"].GetString()
	publicKeyPath, _ := flags["public"].GetString()
	inputFilePath, _ := flags["input"].GetString()
	outputFilePath, _ := flags["output"].GetString()
	if isDecrypt, _ := flags["decrypt"].GetBool(); isDecrypt == true {
		// Decrypt
		privateKey, err := storage.LoadRSAPrivateKey(privateKeyPath)
		if err != nil {
			fmt.Printf("Cannot load private key from file. Error %s\n", err)
			return
		}
		encryptedContent, err := storage.ReadRSAEncryptedFile(inputFilePath)
		encryptedKey := &big.Int{}
		encryptedKey.SetBytes(encryptedContent.EncryptedKey)
		plainText, err := asymmetric.DecryptFile(encryptedContent.EncryptedContent, privateKey, encryptedKey, encryptedContent.Nonce)
		if err != nil {
			fmt.Printf("Cannot decrypt file. Error %s\n", err)
			return
		}
		err = os.WriteFile(outputFilePath, plainText, 0644)
		if err != nil {
			fmt.Printf("Cannot write decrypted file. Error %s\n", err)
			return
		}

	} else {
		// Encrypt
		publicKey, err := storage.LoadRSAPublicKey(publicKeyPath)
		if err != nil {
			fmt.Printf("Cannot load public key from file. Error %s\n", err)
			return
		}
		plainText, err := storage.GetFileContent(inputFilePath)
		if err != nil {
			fmt.Printf("Cannot read file to decrypt. Error: %s\n", err)
			return
		}
		cipherText, nonce, encryptedKey, err := asymmetric.EncryptFile(plainText, publicKey)
		if err != nil {
			fmt.Printf("Cannot encrypt file. Error: %s\n", err)
			return
		}
		payload := &storage.GobRSAEncrypted{
			EncryptedContent: cipherText,
			EncryptedKey:     encryptedKey.Bytes(),
			Nonce:            nonce,
		}
		err = storage.WriteRSAEncryptedFile(outputFilePath, payload)
		if err != nil {
			fmt.Printf("Cannot write file. Error: %s\n", err)
			return
		}
	}

}

func generateKeyAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	fileName, _ := flags["name"].GetString()
	privateKey, publicKey, err := asymmetric.GenerateKey()
	if err != nil {
		fmt.Printf("Cannot generate a new key pair. Error %s\n", err)
		return
	}
	marshalledD, err := privateKey.D.MarshalText()
	if err != nil {
		fmt.Printf("Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	marshalledN, err := privateKey.N.MarshalText()
	if err != nil {
		fmt.Printf("Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	marshalledD = append(marshalledD, '.')
	transformedPrivateKey := append(marshalledD, marshalledN...)
	marshalledE, err := publicKey.E.MarshalText()
	if err != nil {
		fmt.Printf("Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	marshalledN, err = publicKey.N.MarshalText()
	if err != nil {
		fmt.Printf("Cannot transform private key to store locally. Error %s\n", err)
		return
	}
	marshalledE = append(marshalledE, '.')
	transformedPublicKey := append(marshalledE, marshalledN...)
	err = os.WriteFile(fileName+".key", transformedPrivateKey, 0600)
	if err != nil {
		fmt.Printf("Cannot write private key to file. Error %s\n", err)
		return
	}
	err = os.WriteFile(fileName+".pub", transformedPublicKey, 0644)
	if err != nil {
		fmt.Printf("Cannot write public key to file. Error %s\n", err)
		return
	}
}
