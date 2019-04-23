/*!
 * go-rs/aesgcm
 * Copyright(c) 2019 Roshan Gade
 * MIT Licensed
 */
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

// Reference: https://golang.org/pkg/crypto/cipher
// Reference: https://software.intel.com/en-us/articles/aes-gcm-encryption-performance-on-intel-xeon-e5-v3-processors

type AESGCM struct {
	aesgcm cipher.AEAD
	nonce  []byte // common salt/nonce
}

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
// salt/nonce should be optional
func (c *AESGCM) Config(cipherKey string, salt string) (err error) {
	var block cipher.Block

	block, err = aes.NewCipher([]byte(cipherKey))
	if err != nil {
		return
	}

	// should use NewGCM, which is more resistant to misuse
	c.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	if salt != "" {
		c.nonce, err = hex.DecodeString(salt)
		if err != nil {
			return
		}
	}
	return
}

/**
 * Encrypt text
 */
func (c *AESGCM) Encrypt(text string) (val string, err error) {
	val = hex.EncodeToString(c.aesgcm.Seal(nil, c.nonce, []byte(text), nil))
	return
}

/**
 * Encrypt text with nonce
 */
func (c *AESGCM) EncryptWithNonce(text string, nonce string) (val string, err error) {
	data := []byte(text)
	_nonce, err := hex.DecodeString(nonce)
	if err != nil {
		return
	}

	val = hex.EncodeToString(c.aesgcm.Seal(nil, _nonce, data, nil))
	return
}

/**
 * Decrypt string
 */
func (c *AESGCM) Decrypt(text string) (val string, err error) {
	data, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}

	data, err = c.aesgcm.Open(nil, c.nonce, data, nil)
	if err != nil {
		return
	}

	val = string(data)
	return
}

/**
 * Decrypt string with nonce
 */
func (c *AESGCM) DecryptWithNonce(text string, nonce string) (val string, err error) {
	data, err := hex.DecodeString(text)
	if err != nil {
		return
	}

	_nonce, err := hex.DecodeString(nonce)
	if err != nil {
		return
	}

	data, err = c.aesgcm.Open(nil, _nonce, data, nil)
	if err != nil {
		return
	}

	val = string(data)
	return
}
