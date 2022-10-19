package main

import (
	"fmt"
	"os"

	"github.com/thatisuday/commando"
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
		AddArgument("file", "input file", "./myFile").
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
	filePath := args["file"].Value
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Println("Invalid file path.")
		os.Exit(1)
	}
	hashedKey := symmetric.TransformKey(key)
	if isDecrypt, _ := flags["decrypt"].GetBool(); isDecrypt == true {
		if algorithm == "ecb" {
			cipherText, err := storage.GetFileContent(filePath)
			if err != nil {
				fmt.Printf("Cannot read file to decrypt. Error: %s\n", err)
			}
			plainText, err := symmetric.DecryptECB(cipherText, hashedKey[:])
			if err != nil {
				fmt.Printf("Decryption failed.\n %s", err)
				return
			}
			fmt.Printf("%b\n", plainText)
		} else if algorithm == "ctr" {

		} else if algorithm == "gcm" {

		} else {
			fmt.Println("Invalid algorithm given.")
			return
		}

	} else {
		// Encryption
		if algorithm == "ecb" {
			plainText, err := storage.GetFileContent(filePath)
			if err != nil {
				fmt.Printf("Cannot read file to decrypt. Error: %s\n", err)
			}
			cipherText, err := symmetric.EncryptECB(plainText, hashedKey[:])
			if err != nil {
				fmt.Printf("Decryption failed.\n %s", err)
				return
			}
			fmt.Println(cipherText)
		} else if algorithm == "ctr" {

		} else if algorithm == "gcm" {

		} else {
			fmt.Println("Invalid algorithm given.")
			return
		}

	}
}

func asymmetricFileEncryptionAction(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {

}
