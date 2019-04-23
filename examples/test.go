package main

import (
	"fmt"
	"github.com/go-rs/crypto"
)

func main() {
	var c crypto.AESGCM

	err := c.Config("0123456789ABCDEF", "001234567890001234567890")

	e, err := c.Encrypt("Hello World!")
	fmt.Println("Encrypted:", e, err)

	d, err := c.Decrypt(e)
	fmt.Println("Decrypted:", d, err)

	///////////////////////////////////////////////

	nonce := "00123456789abb1234567890" // dynamic nonce

	en, err := c.EncryptWithNonce("Hello World!", nonce)
	fmt.Println("Encrypted:", en, err)

	dn, err := c.DecryptWithNonce(en, nonce)
	fmt.Println("Decrypted:", dn, err)

}
