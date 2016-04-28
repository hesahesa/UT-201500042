package main

import (
	"fmt"
	"net"
	"bufio"
	"crypto/aes"
	"crypto/rsa"
	"io/ioutil"
	"encoding/pem"
	"net"
	"bufio"
)

func main() {
	// read .pem from files
	pemA, _ := ioutil.ReadFile("public_key_A.pem")
	pemB, _ := ioutil.ReadFile("public_key_B.pem")
	pemC, _ := ioutil.ReadFile("public_key_C.pem")
	pemCache, _ := ioutil.ReadFile("public_key_Cache.pem")

	// decode pubkey
	pubKeyA, _ := pem.Decode(pemA)
	pubKeyB, _ := pem.Decode(pemB)
	pubKeyC, _ := pem.Decode(pemC)
	pubKeyCache, _ := pem.Decode(pemCache)

	// TODO : use pubkey, generate IV, encrypt and stuffs

	originalMsg := "4501543 and KELONG_STUDENT_NUMBER"
	encodedOriginalMsg := []byte(originalMsg)

	var encodedFinalMessage []byte

	// connect to socket
	conn, err := net.Dial("tcp", "pets.ewi.utwente.nl:52096")
	if err != nil {
		fmt.Println("error occured when connecting")
	}

	// write to socket
	conn.Write(uint32(len(encodedFinalMessage)))
	conn.Write(encodedFinalMessage)
	response, err := bufio.NewReader(conn).ReadString('\n')
	fmt.Println(response)
}