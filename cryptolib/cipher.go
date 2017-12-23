package cryptolib

import (
    "crypto/aes"
    "errors"
)

/**
Encrypt or decrypt text using AES in ECB mode.

This function assumes properly padded inputs and will not handle padding.

ECB (Electronic Codebook) is an INSECURE method of encrypting a block cipher.
Because it just repeats the same key without modification, it's easy to detect,
and it leaks information about the encrypted data. If you're using this method,
it should be for some security research or similar project (like cryptopals!).
There is a reason the go dev team decided not to include ECB mode in the libs.

Again, IF YOU ARE USING THIS TO ENCRYPT REAL THINGS THOSE THINGS ARE BROKEN.

Inputs:
    ciphertext []byte: The text to decrypt. Must be a multiple of 16 bytes.
    key []byte: The key for AES. Must be 16, 24, or 32 bytes

Outputs:
    []byte: The plaintext produced by decrypting through AES-ECB
    error: Error if key or text has an invalid size
*/
func DecryptAesEcb(ciphertext []byte, key []byte) ([]byte, error) {
    // Check that the ciphertext is divisible into 16 byte blocks
    if len(ciphertext) % aes.BlockSize != 0 {
        return nil, errors.New("Text is not a multiple of cipher blocksize")
    }

    // Create an AES cipher block using the key. AES library will handle size
    // check here and return an error if the key is not a valid length
    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    out := make([]byte, len(ciphertext))
    for block := 0; block < len(ciphertext) / aes.BlockSize; block++ {
        blockStart := block * aes.BlockSize;
        blockEnd := (block + 1) * aes.BlockSize;
        cipher.Decrypt(out[blockStart:blockEnd], ciphertext[blockStart:blockEnd])
    }

    return out, nil
}

/**
Detect if a given ciphertext was encrypted with AES in ECB mode.

Looks for duplicate blocks to detect the presence of ECB mode. This is easily
generalizable to _any_ ECB block cipher by just allowing a variable block size.
*/
func DetectAesEcbMode(ciphertext []byte) bool {
    if len(ciphertext) % aes.BlockSize != 0 {
        // The ciphertext isn't AES encrypted (or is corrupted), so detection
        // should return false
        return false
    }

    // TODO(dylan): I'm worried about this methodology. If a byte array contains
    // a null character, does go include that in the string, or terminate the
    // string there?
    blockFreq := map[string]int {}
    for blockNum := 0; blockNum < len(ciphertext) / aes.BlockSize; blockNum++ {
        blockStart := blockNum * aes.BlockSize;
        blockEnd := (blockNum + 1) * aes.BlockSize;
        block := ciphertext[blockStart:blockEnd]
        blockFreq[string(block)] += 1
    }

    for _, freq := range blockFreq {
        // Repeating block found
        if freq > 1 {
            return true
        }
    }
    return false
}
