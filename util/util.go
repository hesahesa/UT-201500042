package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func GenSliceOfBytes(n int, m int) [][]byte {
	bs := make([][]byte, m)
	for i := range bs {
		bs[i] = GenBytes(n)
	}
	return bs
}

func GenBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func ReadAllPubKeys(fs []string) []*rsa.PublicKey {
	pks := make([]*rsa.PublicKey, len(fs))
	for i, f := range fs {
		pks[i] = ReadPubKey(f)
	}
	return pks
}

func ReadPubKey(f string) *rsa.PublicKey {
	// read .pem from files
	blockA, _ := ioutil.ReadFile(f)
	pemA, _ := pem.Decode(blockA)

	pub, err := x509.ParsePKIXPublicKey(pemA.Bytes)
	if err != nil {
		panic(err)
	}

	rsaPk, ok := pub.(*rsa.PublicKey)
	if !ok {
		panic("value returned from ParsePKIXPublicKey was not an RSA public key")
	}

	return rsaPk
}
