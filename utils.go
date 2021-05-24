package goEncrypt

type ErrCipherKey struct{}

func (a ErrCipherKey) Error() string {
	return "The secret key is wrong and cannot be decrypted. Please chec"
}

type ErrKeyLengthSixteen struct{}

func (e ErrKeyLengthSixteen) Error() string {
	return "a sixteen or twenty-four or thirty-two length secret key is required"
}

type ErrKeyLengthEight struct{}

func (a ErrKeyLengthEight) Error() string {
	return "a eight-length secret key is required"
}

type ErrKeyLengthTwentyFour struct{}

func (e ErrKeyLengthTwentyFour) Error() string {
	return "a twenty-four-length secret key is required"
}

type ErrPaddingSize struct{}

func (e ErrPaddingSize) Error() string {
	return "padding size error please check the secret key or iv"
}

type ErrIvAes struct{}

func (e ErrIvAes) Error() string {
	return "a sixteen-length ivaes is required"
}

type ErrIvDes struct{}

func (e ErrIvDes) Error() string {
	return "a eight-length ivdes key is required"
}

const (
	ivaes = "changeme12345678"
	ivdes = "changeme"

	privateKeyPrefix = "RSA PRIVATE KEY "
	publicKeyPrefix  = "RSA PUBLIC KEY "

	eccPrivateKeyPrefix = "ECC PRIVATE KEY "
	eccPublicKeyPrefix  = "ECC PUBLIC KEY "
)
