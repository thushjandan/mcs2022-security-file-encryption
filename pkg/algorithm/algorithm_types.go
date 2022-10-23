package algorithm

type EncryptionAlgorithm uint8

// Enum for algorithm types
const (
	INVALID_ALG EncryptionAlgorithm = 0
	ECB_ALG                         = 1
	CTR_ALG                         = 2
	GCM_ALG                         = 3
	RSA_ALG                         = 4
)
