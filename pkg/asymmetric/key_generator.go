package asymmetric

import (
	"crypto/rand"
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

func GenerateKey() (*RSAPrivateKey, *RSAPublicKey, error) {
	// Find p with a size of 2048
	p, err := rand.Prime(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// Find q with a size of 2048
	q, err := rand.Prime(rand.Reader, 2048)
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
