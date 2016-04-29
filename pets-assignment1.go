package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
)

import "github.com/hesahesa/UT-201500042/util"

func wrapOnce(m []byte, key []byte, iv []byte, pk *rsa.PublicKey) []byte {
	// padded by pkcs7
	pt, err := util.Pad(m, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// make space for ciphertext
	ctAES := make([]byte, len(pt))

	// set up AES
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ctAES, pt)

	// set up RSA
	ctRSA, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pk, append(key, iv...), nil)
	if err != nil {
		panic(err)
	}

	return append(ctRSA, ctAES...)
}

func wrap(m []byte, keys [][]byte, ivs [][]byte, pks []*rsa.PublicKey) []byte {
	if len(keys) != len(ivs) || len(keys) != len(pks) {
		panic("keys, ivs and pks must have the same length!")
	}

	for i := range keys {
		fmt.Println("Wrapping", keys[i], ivs[i], pks[i])
		m = wrapOnce(m, keys[i], ivs[i], pks[i])
	}
	return m
}

func main() {
	// generate/read ahe keys
	fmt.Println("Reading keys")
	pks := util.ReadAllPubKeys(
		[]string{
			"public_key_Cache.pem",
			"public_key_C.pem",
			"public_key_B.pem",
			"public_key_A.pem",
		})
	ivs := util.GenSliceOfBytes(aes.BlockSize, 4)
	keys := util.GenSliceOfBytes(aes.BlockSize, 4)

	// create the message
	tim := make([]byte, 8)
	copy(tim, "TIM")
	netid := []byte("4501543")
	m := append(tim, netid...)

	// wrap the message
	ct := wrap(m, keys, ivs, pks)
	ctLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ctLen, uint32(len(ct)))

	// connect to socket
	addr := "pets.ewi.utwente.nl:52096"
	fmt.Println("Connecting to", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}

	// write to socket
	fmt.Println("Sending message", ct)
	conn.Write(ctLen)
	conn.Write(ct)
	if conn.Close() != nil {
		panic(err)
	}
}
