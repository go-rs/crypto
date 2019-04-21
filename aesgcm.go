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
//Reference to: https://software.intel.com/en-us/articles/aes-gcm-encryption-performance-on-intel-xeon-e5-v3-processors

type AESGCM struct {
	aesgcm cipher.AEAD
	nonce  []byte // common salt/nonce
}

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
// salt/nonce should be optional
func (c *AESGCM) Init(cipherKey string, salt string) error {
	var block cipher.Block
	var err error

	block, err = aes.NewCipher([]byte(cipherKey))
	if err != nil {
		return err
	}

	// should use NewGCM, which is more resistant to misuse
	c.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	if salt != "" {
		c.nonce, err = hex.DecodeString(salt)
		if err != nil {
			return err
		}
	}
	return nil
}

/**
 * Encrypt text
 */
func (c *AESGCM) Encrypt(text string) (string, error) {
	return hex.EncodeToString(c.aesgcm.Seal(nil, c.nonce, []byte(text), nil)), nil
}

/**
 * Encrypt text with nonce
 */
func (c *AESGCM) EncryptWithNonce(text string, nonce string) (string, error) {
	data := []byte(text)
	_nonce, err := hex.DecodeString(nonce)
	if err != nil {
		println(err.Error())
		return "", err
	}
	return hex.EncodeToString(c.aesgcm.Seal(nil, _nonce, data, nil)), nil
}

/**
 * Decrypt string
 */
func (c *AESGCM) Decrypt(text string) (string, error) {
	data, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}
	data, err = c.aesgcm.Open(nil, c.nonce, data, nil)
	return string(data), err
}

/**
 * Decrypt string with nonce
 */
func (c *AESGCM) DecryptWithNonce(text string, nonce string) (string, error) {
	data, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}
	_nonce, err := hex.DecodeString(nonce)
	if err != nil {
		return "", err
	}
	data, err = c.aesgcm.Open(nil, _nonce, data, nil)
	return string(data), err
}
