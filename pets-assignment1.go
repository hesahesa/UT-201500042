package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"
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
	defer func() {
		if conn.Close() != nil {
			panic(err)
		}
	}()

	// write to socket n times
	fmt.Println("Sending message...")
	for i := 0; i < *n; i++ {
		conn.Write(ctLen)
		conn.Write(ct)
	}
}

func getCache() []byte {
	resp, err := http.Get("http://pets.ewi.utwente.nl:63936/log/cache")
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	return body
}

func writeCacheToFile(fname string) {
	var prev []byte
	body := getCache()

	if bytes.Equal(prev, body) {
		prev = body
		fmt.Println(fname)
		err := ioutil.WriteFile(fname+".txt", body, 0644)
		if err != nil {
			panic(err)
		}
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
	contmod := flag.Bool("continuous", false, "enable continuous mode; n and msg flags are ignored")
	delay := flag.Int("delay", 0, "delay in seconds between sending messages, only in continuous mode")
	flag.Parse()

	if *contmod {
		fmt.Println("continuous mode")
		ctr := 1
		for {
			*msg = strconv.Itoa(ctr)
			*n = 1
			sendmessage(participant, msg, keys, ivs, pks, n)
			ctr = ctr + 1
			writeCacheToFile(strconv.Itoa(ctr))
			time.Sleep(time.Duration(*delay) * time.Second)
		}
	} else {
		sendmessage(participant, msg, keys, ivs, pks, n)
		time.Sleep(1 * time.Second)
		fmt.Println(string(getCache()))
	}
}
