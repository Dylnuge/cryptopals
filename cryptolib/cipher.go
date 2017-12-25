package cryptolib

import (
    "crypto/aes"
    "errors"
)

/** INTERNAL FUNCTIONS **/

/**
Internal function to do ECB block processing

Takes either the encrypt or decrypt function of a block cipher as its second
argument.
*/
func processBlockCipherEcb(text []byte, cipherFunc func(dst, src []byte)) []byte {
    out := make([]byte, len(text))
    for block := 0; block < len(text) / aes.BlockSize; block++ {
        blockStart := block * aes.BlockSize;
        blockEnd := (block + 1) * aes.BlockSize;
        cipherFunc(out[blockStart:blockEnd], text[blockStart:blockEnd])
    }
    return out
}

/** PUBLIC FUNCTIONS **/

/**
Encrypt text using AES in ECB mode.

Text will be padded with PKCS#7 padding before being encrypted

ECB (Electronic Codebook) is an INSECURE method of encrypting a block cipher.
Because it just repeats the same key without modification, it's easy to detect,
and it leaks information about the encrypted data. If you're using this method,
it should be for some security research or similar project (like cryptopals!).
There is a reason the go dev team decided not to include ECB mode in the libs.

IF YOU ARE USING THIS TO ENCRYPT REAL THINGS THOSE THINGS ARE BROKEN.

Inputs:
    plaintext []byte: The text to encrypt.
    key []byte: The key for AES. Must be 16, 24, or 32 bytes

Outputs:
    []byte: The ciphertext produced by encrypting through AES-ECB
    error: Error if key or text has an invalid size
*/
func EncryptAesEcb(plaintext []byte, key []byte) ([]byte, error) {
    // Create an AES cipher block using the key. AES library will handle size
    // check here and return an error if the key is not a valid length
    cipherBlock, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    // Pad the plaintext
    paddedPlaintext := PKCS7PadMessage(plaintext, uint(len(key)))

    out := processBlockCipherEcb(paddedPlaintext, cipherBlock.Encrypt)
    return out, nil
}

/**
Decrypt text using AES in ECB mode.

This function assumes properly padded inputs and will not handle padding.

Again, IF YOU ARE USING THIS TO HANDLE REAL THINGS THOSE THINGS ARE BROKEN.

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
    cipherBlock, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    out := processBlockCipherEcb(ciphertext, cipherBlock.Decrypt)
    return out, nil
}

/**
Encrypt text using AES in CBC mode.

Text will be padded with PKCS#7 padding before being encrypted.

CBC (Cipher Block Chaining) is a block cipher mode where each block of plaintext
is XORed against the preceding ciphertext block before being encrypted. The
first block is XORed against an initialization vector.

Inputs:
    plaintext []byte: The text to encrypt.
    key []byte: The key for AES. Must be 16, 24, or 32 bytes
    iv []byte: The initialization vector for CBC mode. Must be 16 bytes.

Outputs:
    []byte: The ciphertext produced by encrypting through AES-CBC
    error: Error if key or text has an invalid size
*/
func EncryptAesCbc(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
    // TODO(dylan): Might be possible to reduce code duplication here, but at
    // some point decomposing these functions becomes more trouble than its
    // worth, since each one is just slightly different.

    // Check that the iv is the same as the blocksize
    if len(iv) != aes.BlockSize {
        return nil, errors.New("IV must be same length as cipher blocks")
    }

    // Create an AES cipher block using the key. AES library will handle size
    // check here and return an error if the key is not a valid length
    cipherBlock, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    // Pad the plaintext
    paddedPlaintext := PKCS7PadMessage(plaintext, uint(len(key)))

    lastCipherBlock := iv
    ciphertext := make([]byte, len(paddedPlaintext))
    for block := 0; block < len(paddedPlaintext) / aes.BlockSize; block++ {
        blockStart := block * aes.BlockSize;
        blockEnd := (block + 1) * aes.BlockSize;

        // XOR the plaintext with the last cipherblock
        plainBlock := paddedPlaintext[blockStart:blockEnd]
        xorPlainBlock := DecryptXor(plainBlock, lastCipherBlock)
        cipherBlock.Encrypt(ciphertext[blockStart:blockEnd], xorPlainBlock)
        lastCipherBlock = ciphertext[blockStart:blockEnd]
    }

    return ciphertext, nil
}

/**
Decrypt text using AES in CBC mode.

Inputs:
    ciphertext []byte: The text to encrypt.
    key []byte: The key for AES. Must be 16, 24, or 32 bytes
    iv []byte: The initialization vector for CBC mode. Must be 16 bytes.

Outputs:
    []byte: The ciphertext produced by encrypting through AES-CBC
    error: Error if key or text has an invalid size
*/
func DecryptAesCbc(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
    // Check that the ciphertext is divisible into 16 byte blocks
    if len(ciphertext) % aes.BlockSize != 0 {
        return nil, errors.New("Text is not a multiple of cipher blocksize")
    }
    // And check that the iv is the same as the blocksize
    if len(iv) != aes.BlockSize {
        return nil, errors.New("IV must be same length as cipher blocks")
    }

    // Create an AES cipher block using the key. AES library will handle size
    // check here and return an error if the key is not a valid length
    cipherBlock, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    lastCipherBlock := iv
    plaintext := make([]byte, len(ciphertext))
    for block := 0; block < len(ciphertext) / aes.BlockSize; block++ {
        blockStart := block * aes.BlockSize;
        blockEnd := (block + 1) * aes.BlockSize;

        // Make a temporary block for the pre-xored plaintext
        plainBlock := make([]byte, aes.BlockSize)

        cipherBlock.Decrypt(plainBlock, ciphertext[blockStart:blockEnd])
        // XOR the plaintext with the last cipherblock
        xorPlainBlock := DecryptXor(plainBlock, lastCipherBlock)
        copy(plaintext[blockStart:blockEnd], xorPlainBlock)
        lastCipherBlock = ciphertext[blockStart:blockEnd]
    }

    return plaintext, nil
}

