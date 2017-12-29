package cryptolib

import (
    "bytes"
    "io/ioutil"
    "testing"
)

// This is cryptopals challenge 7
func TestDecryptAesEcb(t *testing.T) {
    b64Input, err := ioutil.ReadFile("fixtures/aes_ecb_encrypted.txt")
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

func TestEncryptAesEcb(t *testing.T) {
    plaintext, err := ioutil.ReadFile("fixtures/aes_decrypted.txt")
    if err != nil {
        t.Errorf("Test fixture read error %v\n", err)
    }

    b64Output, err := ioutil.ReadFile("fixtures/aes_ecb_encrypted.txt")
    if err != nil {
        t.Errorf("Test fixture read error %v\n", err)
    }
    expectedCiphertext := DecodeBase64(string(b64Output))
    key := []byte("YELLOW SUBMARINE")

    ciphertext, err := EncryptAesEcb(plaintext, key)
    if err != nil {
        t.Errorf("Error occured during decrypt: %v\n", err)
    }

    // HACK the ciphertext is block-aligned, which with PKCS#7 padding means we
    // get an additional block. Drop the last 16 bytes.
    ciphertext = ciphertext[:len(ciphertext) - 16]

    if !bytes.Equal(ciphertext, expectedCiphertext) {
        t.Errorf("Ciphertext does not match fixture:\n%v\n", ciphertext)
    }
}

func TestDecryptAesCbc(t *testing.T) {
    b64Input, err := ioutil.ReadFile("fixtures/aes_cbc_encrypted.txt")
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
    iv := make([]byte, 16)
    plaintext, err := DecryptAesCbc(ciphertext, key, iv)
    if err != nil {
        t.Errorf("Error occured during decrypt: %v\n", err)
    }

    if !bytes.Equal(plaintext, expectedOut) {
        t.Errorf("Decoded plaintext does not match fixture:\n%v\n", plaintext)
    }
}

func TestEncryptAesCbc(t *testing.T) {
    plaintext, err := ioutil.ReadFile("fixtures/aes_decrypted.txt")
    if err != nil {
        t.Errorf("Test fixture read error %v\n", err)
    }

    b64Output, err := ioutil.ReadFile("fixtures/aes_cbc_encrypted.txt")
    if err != nil {
        t.Errorf("Test fixture read error %v\n", err)
    }
    expectedCiphertext := DecodeBase64(string(b64Output))
    key := []byte("YELLOW SUBMARINE")

    // Step 2: Decrypt it using the key provided
    iv := make([]byte, 16)
    ciphertext, err := EncryptAesCbc(plaintext, key, iv)
    if err != nil {
        t.Errorf("Error occured during decrypt: %v\n", err)
    }

    // HACK the ciphertext is block-aligned, which with PKCS#7 padding means we
    // get an additional block. Drop the last 16 bytes.
    ciphertext = ciphertext[:len(ciphertext) - 16]

    if !bytes.Equal(ciphertext, expectedCiphertext) {
        t.Errorf("Ciphertext does not match fixture:\n%v\n", ciphertext)
    }
}
