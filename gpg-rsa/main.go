package main

import (
	"fmt"
	"io/ioutil"
)

func main() {
	testPubFile := "rsa_public_key.pem"
	testContentFile := "hello.txt"
	testSignFile := "hello.sig"

	pubBytes, err := ioutil.ReadFile(testPubFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	signBytes, err := ioutil.ReadFile(testSignFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	contentBytes, err := ioutil.ReadFile(testContentFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = SHA256Verify(pubBytes, contentBytes, signBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Success!")
}
