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

func chooseE(totient *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	for {
		e, err := rand.Prime(rand.Reader, 999)
		if err != nil {
			return nil, err
		}
		z := big.Int{}
		if z.GCD(nil, nil, e, totient).Cmp(one) == 0 {
			return e, nil
		}
	}

}

func GenerateKey() (*RSAPrivateKey, *RSAPublicKey, error) {
	p, err := rand.Prime(rand.Reader, 1000)
	if err != nil {
		return nil, nil, err
	}
	q, err := rand.Prime(rand.Reader, 1000)
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
	d := big.Int{}
	d.ModInverse(e, totient)
	privateKey := &RSAPrivateKey{
		D: e,
		N: n,
	}
	publicKey := &RSAPublicKey{
		E: e,
		N: n,
	}

	return privateKey, publicKey, nil
}
