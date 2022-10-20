package main

import (
	"fmt"
	"os"

	"github.com/thatisuday/commando"
	algoType "github.com/thushjandan/mcs2022-security-file-encryption/pkg/algorithm"
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
		AddFlag("algorithm,a", "asymmetric algorthm to choose", commando.String, "rsa")
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

}
