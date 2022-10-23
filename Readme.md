# Security Assignment #1
This project implements a file encryption command line application, which encrypts & decrypts files with 3 different symmetric block ciphers and with textbook RSA.

# Download precompiled binaries
Precompiled binaries for several OS can be found here: [Github Releases](https://github.com/thushjandan/mcs2022-security-file-encryption/releases/tag/v1.0.0)
Only linux_amd64 binary has been tested.

# Build on Linux or Windows
```bash
# Download dependencies
go mod download
# Build binary called fenc
go build -o fenc cmd/fenc/main.go
```

# Run Unit tests
```bash
go test -v ./...
```

# Usage
## Encrypt file with Electronic Codebook (ECB)
Encrypt file with ECB and shared key supersecretkey
```
./fenc sym -a ecb -k supersecretkey -i plaintext.txt -o encryptedfile.txt.enc
```
## Decrypt file with Electronic Codebook (ECB)
Decrypt file with ECB and shared key supersecretkey
```
./fenc sym -d -a ecb -k supersecretkey -i encryptedfile.txt.enc -o plaintext.txt
```
## Encrypt file with CTR
Encrypt file with CTR and shared key supersecretkey
```
./fenc sym -a ctr -k supersecretkey -i plaintext.txt -o encryptedfile.txt.enc
```

## Decrypt file with CTR
Decrypt file with CTR and shared key supersecretkey
```
./fenc sym -d -a ctr -k supersecretkey -i encryptedfile.txt.enc -o plaintext.txt
```
## Encrypt file with AES-GCM
Encrypt file with AES-GCM and shared key supersecretkey
```
./fenc sym -a gcm -k supersecretkey -i plaintext.txt -o encryptedfile.txt.enc
```

## Decrypt file with AES-GCM
Decrypt file with AES-GCM and shared key supersecretkey
```
./fenc sym -d -a gcm -k supersecretkey -i encryptedfile.txt.enc -o plaintext.txt
```

## RSA Key generation
Generates a public/private key pair with bitsize of 2048 bits
```
./fenc generate
```
Generates a public/private key pair with bitsize of 4096 bits
```
./fenc generate -b 4096
```
Generates a public/private key pair with a defined filename and bitsize of 4096
```
./fenc generate -n supersecret -b 4096
```
## Encrypt file with textbook RSA
Encrypt file with public key myKey.pub
```
./fenc asym -p ./myKey.pub -i plaintext.txt -o encryptedfile.txt.enc
```

## Decrypt file with textbook RSA
Decrypt file with private key myKey.key
```
./fenc asym -d -k ./myKey.key -i encryptedfile.txt.enc -o plaintext.txt
```

# Help
Help page for main command
```
./fenc -h

This CLI tool helps you encrypt and decrypt files with several symmetric and text book RSA encryption algorithm.

Usage:
   fenc {flags}
   fenc <command> {flags}

Commands: 
   asym                          file encryption using asymmetric algortihm
   generate                      Generates private public key pair
   help                          displays usage informationn
   sym                           file encryption using symmetric algorithms
   version                       displays version number

Flags: 
   -h, --help                    displays usage information of the application or a command (default: false)
   -v, --version                 displays version number (default: false)
```
Arguments for symmetric encryption subcommand
```
 ./fenc sym -h



Usage:
   fenc {flags}

Flags: 
   -a, --algorithm               symmetric algortihm to choose (default: gcm)
   -d, --decrypt                 decrypt or encrypt. If flag is set, then file will be decrypted. Otherwise file will be encrypted (default: false)
   -h, --help                    displays usage information of the application or a command (default: false)
   -i, --input                   input file (default: ./myFile)
   -k, --key                     passphrase used as key (default: default)
   -o, --output                  output file (default: ./myFile.output)
```

Arguments for key generation subcommand
```
./fenc generate -h



Usage:
   fenc {flags}

Flags: 
   -h, --help                    displays usage information of the application or a command (default: false)
   -n, --name                    file name of newly generates key pairs (default: myKey)
```

Arguments for symmetric encryption subcommand
```
/fenc asym -h



Usage:
   fenc {flags}

Flags: 
   -a, --algorithm               asymmetric algorthm to choose (default: rsa)
   -d, --decrypt                 decrypt or encrypt. If flag is set, then file will be decrypted. Otherwise file will be encrypted (default: false)
   -h, --help                    displays usage information of the application or a command (default: false)
   -i, --input                   input file (default: ./myFile)
   -o, --output                  output file (default: ./myFile.output)
   -k, --private                 private key (default: ./myKey.key)
   -p, --public                  private key (default: ./myKey.pub)
```