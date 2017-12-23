package cryptolib

import (
    "bytes"
    "io/ioutil"
    "testing"
)

// This is cryptopals challenge 7
func TestDecryptAesEcb(t *testing.T) {
    b64Input, err := ioutil.ReadFile("fixtures/aes_encrypted.txt")
    if err != nil {
        t.Errorf("Test fixture read error %v\n", err)
    }
    expectedOut, err := ioutil.ReadFile("fixtures/aes_decrypted.txt")
    if err != nil {
        t.Errorf("Test fixture read error %v\n", err)
    }
    ciphertext := DecodeBase64(string(b64Input))
    key := []byte("YELLOW SUBMARINE")

    // Step 2: Decrypt it using the key provided
    plaintext, err := DecryptAesEcb(ciphertext, key)
    if err != nil {
        t.Errorf("Error occured during decrypt: %v\n", err)
    }

    if !bytes.Equal(plaintext, expectedOut) {
        t.Errorf("Decoded plaintext does not match fixture:\n%v\n", plaintext)
    }
}
