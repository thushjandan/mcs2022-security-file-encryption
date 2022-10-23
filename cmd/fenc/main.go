package main

import (
	"github.com/thatisuday/commando"
	"github.com/thushjandan/mcs2022-security-file-encryption/pkg/controller"
)

func main() {
	commando.
		SetExecutableName("fenc").
		SetVersion("v1.0.0").
		SetDescription("This CLI tool helps you encrypt and decrypt files with several symmetric and text book RSA encryption algorithm.")

	// Register subcommand sym
	commando.Register("sym").
		SetShortDescription("file encryption using symmetric algorithms").
		AddFlag("algorithm,a", "symmetric algortihm to choose", commando.String, "gcm").
		AddFlag("decrypt,d", "decrypt or encrypt. If flag is set, then file will be decrypted. Otherwise file will be encrypted", commando.Bool, false).
		AddFlag("key,k", "passphrase used as key", commando.String, "default").
		AddFlag("input,i", "input file", commando.String, "./myFile").
		AddFlag("output,o", "output file", commando.String, "./myFile.output").
		SetAction(controller.SymmetricFileEncryptionAction)

	// Register subcommand asym
	commando.Register("asym").
		SetShortDescription("file encryption using asymmetric algortihm").
		AddFlag("algorithm,a", "asymmetric algorthm to choose", commando.String, "rsa").
		AddFlag("decrypt,d", "decrypt or encrypt. If flag is set, then file will be decrypted. Otherwise file will be encrypted", commando.Bool, false).
		AddFlag("private,k", "private key", commando.String, "./myKey.key").
		AddFlag("public,p", "private key", commando.String, "./myKey.pub").
		AddFlag("input,i", "input file", commando.String, "./myFile").
		AddFlag("output,o", "output file", commando.String, "./myFile.output").
		SetAction(controller.AsymmetricFileEncryptionAction)

	// Register subcommand generate
	commando.Register("generate").
		SetShortDescription("Generates private public key pair").
		AddFlag("name,n", "file name of newly generates key pairs", commando.String, "myKey").
		AddFlag("bits,b", "bit size of the key", commando.Int, 2048).
		SetAction(controller.GenerateKeyAction)
	commando.Parse(nil)

}
