package main

import (
    "bytes"
    "fmt"
    "github.com/dylnuge/cryptopals/cryptolib"
    "math/rand"
    "time"
)

// This function uses a potentially insecure psueodrandom number generator
// based on a pregenerated seed. This is _fine_ for what we're doing (making
// random AES keys in order to test some detection functionality) but not cool
// for real crypto. "crypto/rand" has randomness functions which use an
// available unblocking cryptographically secure source (e.g. /dev/urandom)
// That all said, Go's rand library does not automatically pick a random seed on
// import or first call, and will just use 1 as the seed, so seed the RNG before
// calling this function.
// Also this is cool, if unrelated: https://www.2uo.de/myths-about-urandom/
func genRandomBytes(bytes uint) []byte {
    // Wow that's a lot of comment for such a simple function. REMEMBER TO SET
    // THE SEED because this isn't Python and it's not done for you already.
    key := make([]byte, bytes)
    rand.Read(key)
    return key
}

func randEncrypt(data []byte) (out []byte) {
    key := genRandomBytes(16)
    // randomly append between 5 and 10 random bytes to the front and back
    randCount := uint((6*rand.Float32()) + 5)
    frontPad := genRandomBytes(randCount)
    randCount = uint((6*rand.Float32()) + 5)
    backPad := genRandomBytes(randCount)
    paddedData := make([]byte, 0, len(frontPad) + len(data) + len(backPad))
    paddedData = append(paddedData, frontPad...)
    paddedData = append(paddedData, data...)
    paddedData = append(paddedData, backPad...)

    // Flip a coin to chose between CBC and ECB
    if rand.Float32() >= 0.5 {
        fmt.Println("ECB chosen")
        out, _ = cryptolib.EncryptAesEcb(paddedData, key)
    } else {
        fmt.Println("CBC chosen")
        iv := genRandomBytes(16)
        out, _ = cryptolib.EncryptAesCbc(paddedData, key, iv)
    }
    return
}

func challenge11() {
    // Seed RNG with the time this program was started.
    rand.Seed(time.Now().UnixNano())
    data := []byte("Some arbitrary daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaata that will be encrypted. The quick brown fox jumps over the craaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaazy dog")
    ciphertext := randEncrypt(data)
    if cryptolib.DetectEcbMode(ciphertext, 16) {
        fmt.Println("ECB detected")
    } else {
        fmt.Println("CBC detected")
    }
}

func secretEncrypter(userInput []byte) []byte {
    secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    decodedSecret := cryptolib.DecodeBase64(secret)
    // Use consistent random key ("random" seed was chosen arbitrairly by me)
    rand.Seed(1711986)
    key := genRandomBytes(16)
    message := append(userInput, decodedSecret...)
    out, err := cryptolib.EncryptAesEcb(message, key)
    if err != nil {
        fmt.Printf("ERROR encoding message %v\n", err)
    }
    return out
}

// Build a map from ciphertexts to plaintext bytes
func buildCipherMappings(knownBlock []byte, blocksize int) map[string]byte {
    if len(knownBlock) != blocksize - 1 {
        fmt.Println("Sanity check failed, buildCipherMappings must have all but one byte\n")
        return nil
    }

    output := map[string]byte{}
    // for every possible byte
    for i := 0; i <= int(^byte(0)); i++ {
        guessByte := byte(i)
        input := append(knownBlock, guessByte)
        ciphertext := secretEncrypter(input)
        cipherblock := ciphertext[0:blocksize]
        output[string(cipherblock)] = guessByte
    }

    return output
}

// This is Cryptopals Challenge 12: Write an exploit to decrypt ECB block
// ciphers when you're able to feed in part (but not all) of the plaintext to
// the beginning of the message
func crackECBMode() {
    // Step 1: discover block size of cipher being used by secret encrypter. If
    // this succeeds, the cipher is using ECB. If it fails, the cipher may not
    // be using ECB, or the cipher may be using a blocksize larger than 64 bytes
    // (We know it's using a 16 byte block cipher, specifically, AES)
    blocksize, err := cryptolib.DetermineEcbBlocksize(secretEncrypter, 64)
    if err != nil {
        fmt.Printf("%v\n", err)
        return
    }

    fmt.Printf("ECB block cipher detected! Blocksize: %v bytes\n", blocksize)

    // Step 2: Determine the number of blocks in the message without user
    // content. This is probably (not certainly) padded somehow, which may
    // produce some issues at the end of the message decryption. We'll get to
    // those in a bit.
    ciphertext := secretEncrypter([]byte(""))
    if len(ciphertext) % blocksize != 0 {
        fmt.Printf("Original blocksize guess was incorrect.\n")
        return
    }
    unknownBlocks := len(ciphertext) / blocksize
    fmt.Printf("Secret message block length: %v\n", unknownBlocks)

    // Step 3: Build a pretext block we can use to offset the message so we're
    // only dealing with one unknown byte in a plaintext at a time. Block
    // ciphers should have identical length input and output blocks, meaning we
    // can in ECB mode map each block in the pretext to an output block.
    knownPretext := make([]byte, blocksize)
    for i := 0; i < blocksize; i++ {
        // Strictly this is unnecessary; make initializes to null ('\x00') bytes
        // anyways, but this makes things we print out to the command line
        // more readable.
        knownPretext[i] = 'A'
    }
    knownSecret := make([]byte, 0, len(ciphertext))

    // Step 4: For each unknown byte in the secret message, encrypt and build a
    // dictionary of possible plaintext input and ciphertext output blocks.
    // Let's assume nothing about the plaintext and therefore check all 256
    // possible bytes, not just likely ASCII ones.
    for i := 0; i < len(ciphertext); i++ {
        // Calculate byte offset as blocksize minus the byte we're looking for
        // modded by the blocksize. The byte we're looking for is one beyond the
        // last one we have; e.g. if we're looking at index 0, we're looking for
        // the first byte, at index 1, we're looking for the second byte.
        // byteOffset will tell us how much to pad the plaintext and block will
        // tell us where to look.
        byteOffset := blocksize - ((i+1) % blocksize)
        // TODO this math seems annoyingly complex. It should be cleaner to
        // "count down" the number of bytes we need to offset by
        if byteOffset == blocksize {
            byteOffset = 0
        }
        pretext := knownPretext[0:byteOffset]
        knownBlock := make([]byte, 0, blocksize - 1)
        // Build the known block from the last available characters of the known
        // secret, and the pretext if we're still in the first block
        // TODO again this code feels very complex for what it's actually doing
        if len(knownSecret) < blocksize - 1 {
            // If we're still in the first block, append from the pretext
            for j := i; j < blocksize - 1; j++ {
                knownBlock = append(knownBlock, 'A')
            }
            knownBlock = append(knownBlock, knownSecret...)
        } else {
            knownBlock = knownSecret[len(knownSecret) - (blocksize - 1):]
        }

        outputs := buildCipherMappings(knownBlock, blocksize)

        // Step 5: Encrypt the secret, grab the block we're looking at, and get
        // the byte from the cipher mappings we just built
        currentCiphertext := secretEncrypter(pretext)
        block := i / blocksize
        blockStart := blocksize * block
        blockEnd := blocksize * (block + 1)
        currentCipherblock := currentCiphertext[blockStart:blockEnd]
        // At the end here, we find a lot of "0" blocks, since the padding is
        // changing. This is OK, so we'll just keep it here. We could also
        // strictly check that the cipherblock was in the map, and stop when we
        // hit a point where this isn't working anymore
        nextByte := outputs[string(currentCipherblock)]
        knownSecret = append(knownSecret, nextByte)
        fmt.Printf("Found byte %v, known secret is now %v\n", nextByte, string(knownSecret))
    }
}

func main() {
    if !bytes.Equal(secretEncrypter([]byte("mytest")), secretEncrypter([]byte("mytest"))) {
        fmt.Println("Sanity check failed, key is changing between encodings\n")
    }
    crackECBMode()
}
