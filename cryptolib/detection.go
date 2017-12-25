package cryptolib

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

    // TODO(dylan): I'm worried about this methodology. If a byte array contains
    // a null character, does go include that in the string, or terminate the
    // string there?
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
