package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
)

func genRandByte(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func readPubKey() *rsa.PublicKey {
	// read .pem from files
	blockA, _ := ioutil.ReadFile("public_key_A.pem")
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

func main() {

	// plaintext padded by pkcs7
	pt, err := pkcs7Pad([]byte("this is some plaintext that we're going to send"), aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// make space for ciphertext
	ctAES := make([]byte, len(pt))

	// set up AES
	// TODO what block size do we use? the default is 16
	key := genRandByte(aes.BlockSize)
	iv := genRandByte(aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ctAES, pt)

	// set up RSA
	// TODO EncryptPKCS1v15 isn't vanilla RSA, so this this probably won't work
	pk := readPubKey()
	ctRSA, err := rsa.EncryptPKCS1v15(rand.Reader, pk, append(key, iv...))
	if err != nil {
		panic(err)
	}

	// connect to socket
	conn, err := net.Dial("tcp", "pets.ewi.utwente.nl:52096")
	if err != nil {
		panic(err)
	}

	// write to socket
	finalMsg := append(ctRSA, ctAES...)
	lenMsg := make([]byte, 4)
	binary.BigEndian.PutUint32(lenMsg, uint32(len(finalMsg)))

	conn.Write(lenMsg)
	conn.Write(finalMsg)

	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		panic(err)
	}
	fmt.Println(response)
}
