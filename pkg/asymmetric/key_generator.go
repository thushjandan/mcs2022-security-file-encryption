package asymmetric

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type RSAPublicKey struct {
	E *big.Int
	N *big.Int
}

type RSAPrivateKey struct {
	D *big.Int
	N *big.Int
}

var validKeySize = map[int]bool{
	2048: true,
	4096: true,
	8192: true,
}

// Find a suitable E
func chooseE(totient *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	for {
		e, err := rand.Prime(rand.Reader, 999)
		if err != nil {
			return nil, err
		}
		if e.Cmp(one) == 1 && e.Cmp(totient) < 0 && new(big.Int).GCD(nil, nil, e, totient).Cmp(one) == 0 {
			return e, nil
		}
	}
}

func GenerateKey(keysize int) (*RSAPrivateKey, *RSAPublicKey, error) {
	if _, ok := validKeySize[keysize]; !ok {
		return nil, nil, errors.New("Invalid key size. Only 2048, 4096 & 8192 are allowed")
	}

	// Find p with a size of keysize
	p, err := rand.Prime(rand.Reader, keysize)
	if err != nil {
		return nil, nil, err
	}
	// Find q with a size of keysize
	q, err := rand.Prime(rand.Reader, keysize)
	if err != nil {
		return nil, nil, err
	}
	one := big.NewInt(1)
	n := new(big.Int)
	totient := new(big.Int)
	// n = p * q
	n.Mul(p, q)
	// totient => phi(n) = (p-1) * (q-1)
	totient.Mul(p.Sub(p, one), q.Sub(q, one))
	e, err := chooseE(totient)
	if err != nil {
		return nil, nil, err
	}
	// Calculate d = e^−1 mod totient(n)
	// modular multiplicative inverse
	d := &big.Int{}
	d.ModInverse(e, totient)

	privateKey := &RSAPrivateKey{
		D: d,
		N: n,
	}
	publicKey := &RSAPublicKey{
		E: e,
		N: n,
	}

	return privateKey, publicKey, nil
}
