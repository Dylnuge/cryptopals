package main

import (
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
    data := []byte("Some arbitrary daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaata that will be encrypted. The quick brown fox jumps over the craaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaazy dog")
    ciphertext := randEncrypt(data)
    if cryptolib.DetectEcbMode(ciphertext, 16) {
        fmt.Println("ECB detected")
    } else {
        fmt.Println("CBC detected")
    }
}

func main() {
    // Seed RNG with the time this program was started.
    rand.Seed(time.Now().UnixNano())
    challenge11()
    challenge11()
    challenge11()
    challenge11()
}
