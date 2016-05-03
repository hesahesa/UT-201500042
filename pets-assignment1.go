package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"flag"
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
		m = wrapOnce(m, keys[i], ivs[i], pks[i])
	}
	return m
}

func main() {
	// generate/read the keys
	fmt.Println("Reading keys...")
	pks := util.ReadAllPubKeys(
		[]string{
			"public_key_Cache.pem",
			"public_key_C.pem",
			"public_key_B.pem",
			"public_key_A.pem",
		})
	ivs := util.GenSliceOfBytes(aes.BlockSize, 4)
	keys := util.GenSliceOfBytes(aes.BlockSize, 4)

	// let user specify the message content if needed
	participant := flag.String("participant", "TIM", "name of the participant")
	n := flag.Int("n", 1, "number of messages to send")
	msg := flag.String("msg", "4501543, 4520009", "content of the message")
	flag.Parse()

	// wrap the message to create the ciphertext
	ct := wrap(
		append([]byte(fmt.Sprintf("%-8s", *participant)), []byte(*msg)...),
		keys,
		ivs,
		pks)
	ctLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ctLen, uint32(len(ct)))

	// connect to socket
	addr := "pets.ewi.utwente.nl:52096"
	fmt.Println("Connecting to", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}

	// write to socket n times
	fmt.Println("Sending message...")
	for i := 0; i < *n; i++ {
		conn.Write(ctLen)
		conn.Write(ct)
	}
	if conn.Close() != nil {
		panic(err)
	}
}
