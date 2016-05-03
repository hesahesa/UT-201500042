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

import (
	"github.com/hesahesa/UT-201500042/util"
	"net/http"
	"io/ioutil"
)

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

func sendmessage(participant *string, msg *string, keys [][]byte, ivs [][]byte, pks []*rsa.PublicKey, n *int) {
	// wrap the message to create the ciphertext
	if len(*participant) > 8 {
		*participant = (*participant)[:8]
	}
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
	contmod := flag.Bool("continous", false, "enable continous mode, ignore other flags")
	flag.Parse()

	if *contmod == true {
		// TODO: fire up messages with content = {1,2,3,4,...} continously and read the log
		// TODO: save the response body to file (?) if it is different from before for analysis
		fmt.Println("continous mode")
		resp, err := http.Get("http://pets.ewi.utwente.nl:63936/log/cache")
		if err != nil {
			// handle error
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println(body)
	} else {
		sendmessage(participant, msg, keys, ivs, pks, n)
	}
}
