package main

import (
	"crypto/rsa"
	"fmt"
)

type PrivateKey *rsa.PrivateKey

type Ctx struct{}
type Certificate struct{}

func NewCtxFromFiles(cert_file string, key_file string) (*Ctx, error) {
	panic("not implemented")
	return nil, fmt.Errorf("not implemented")
}
func LoadDHParametersFromPEM(pem_block []byte) (DH, error) {
	panic("not implemented")
	return nil, fmt.Errorf("not implemented")
}
func LoadDHFromBignumWithGenerator(bytes []byte, generator int) (DH, error) {
	panic("not implemented")
	return nil, fmt.Errorf("not implemented")
}

type DH interface {
	GetPublicKey() ([]byte, error)
	GetSharedKey(challenge []byte) ([]byte, error)
}

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	panic("not implemented")
	return nil, fmt.Errorf("not implemented")
}
func GenerateRSAKeyWithExponent(bits int, exponent uint) (*rsa.PrivateKey, error) {
	panic("not implemented")
	return nil, fmt.Errorf("not implemented")
}
