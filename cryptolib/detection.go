package cryptolib

import "errors"

/**
Detect if a given ciphertext was encrypted in ECB mode.

Looks for duplicate blocks to detect the presence of ECB mode. This is easily
generalizable to _any_ ECB block cipher by just allowing a variable block size.
*/
func DetectEcbMode(ciphertext []byte, blocksize int) bool {
    if len(ciphertext) % blocksize != 0 {
        // The ciphertext isn't AES encrypted (or is corrupted), so detection
        // should return false
        return false
    }

    blockFreq := map[string]int {}
    for blockNum := 0; blockNum < len(ciphertext) / blocksize; blockNum++ {
        blockStart := blockNum * blocksize;
        blockEnd := (blockNum + 1) * blocksize;
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

/**
Determine the blocksize of a cipher function presumed to be using an ECB cipher
*/
func DetermineEcbBlocksize(cipherFunc func([]byte) []byte, maxGuess int) (int, error) {
    // We start at 2 because a blocksize of 1 byte is so small that we're nearly
    // guarenteed to find duplicates when running DetectEcbMode, and they're a
    // false positive. As with a lot of this code, we're basically just
    // producing a best guess; there's no guarentee that finding duplicates with
    // a blocksize guess of 4 determines _for sure_ that the blocksize is 4. It
    // should work to "double check" by using three, four, five blocks and
    // confirming we get three, four, five duplicate outputs, but we'll ignore
    // that for now
    for blocksize := 2; blocksize <= maxGuess; blocksize++ {
        // Construct a message that is two "blocks" long
        message := make([]byte, blocksize*2)
        for i := 0; i < blocksize*2; i++ {
            message[i] = 'A'
        }

        // Encrypt the message using the cipher function. This does NOT assume
        // that the cipher function only encrypts the message and no other data
        ciphertext := cipherFunc(message)

        // Detect ECB mode. If detection works, we've found the right blocksize
        if DetectEcbMode(ciphertext, blocksize) {
            return blocksize, nil
        }
    }
    // We should break out of the loop if we found the right blocksize, so we
    // didn't. Return an error
    return 0, errors.New("Cipher not using ECB, not a block cipher, or blocks are longer than maximum guess")
}
