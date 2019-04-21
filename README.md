# Crypto
Text encryption and description, using various mechanisms like AES-GCM, AES-CBC, etc

## AES-GCM
### Config
c.Config({cipher-key}, {nonce})
- cipher-key is required
- nonce/salt is optional, but it is required for Encrypt and Decrypt methods

### How to use?
##### With static nonce
````
var c crypto.AESGCM

err := c.Config("0123456789ABCDEF", "001234567890001234567890")

e, err := c.Encrypt("Hello World!")
fmt.Println("Encrypted:", e, err)

d, err := c.Decrypt(e)
fmt.Println("Decrypted:", d, err)
````

##### With dynamic nonce
````
var c crypto.AESGCM

err := c.Config("0123456789ABCDEF", "")

nonce := "00123456789abb1234567890" // dynamic nonce

en, err := c.EncryptWithNonce("Hello World!", nonce)
fmt.Println("Encrypted:", en, err)

dn, err := c.DecryptWithNonce(en, nonce)
fmt.Println("Decrypted:", dn, err)
````
