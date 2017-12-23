package main

import (
    "bytes"
    "fmt"
    "io/ioutil"
    "github.com/dylnuge/cryptopals/cryptolib"
)

/* Testing functions for problem set 1

These should probably be pulled out into a unit test file. These are the test
cases provided for each problem set.
*/

func challenge3() {
    // And this "real" function isn't a test function at all. I sense a refactor
    // coming in the morning.

    var in string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    var encoded []byte = cryptolib.DecodeHex(in)

    // XORed against a single "character" to me means any byte. I'm not assuming
    // the key is an alphanumeric ASCII code point.
    key, err := cryptolib.CrackSingleByteXor(encoded,
        cryptolib.FrequenciesDifferenceEnglishASCIIScore)
    if err != nil{
        fmt.Println("Challenge 3 decoding FAILED")
        fmt.Printf("Error: %v\n", err)
        return
    }

    plaintext := cryptolib.DecryptXor(encoded, []byte{key})

    fmt.Println("Challenge 3 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(plaintext))
}

func challenge4() {
    data, err := ioutil.ReadFile("data/4.txt")
    if err != nil {
        fmt.Printf("ERROR in file read %v\n", err)
        return
    }

    dataLines := bytes.Split(data, []byte("\n"))
    bestScore := 10000.0
    var bestMsg []byte
    var bestKey byte
    for i := 0; i < len(dataLines); i++ {
        line := dataLines[i]
        encoded := cryptolib.DecodeHex(string(line))
        key, err := cryptolib.CrackSingleByteXor(encoded,
            cryptolib.FrequenciesDifferenceEnglishASCIIScore)

        if err != nil {
            // This line had _no_ candidate XOR, so it's not the right one
            continue;
        }

        canMsg := cryptolib.DecryptXor(encoded, []byte{key})
        canScore, _ := cryptolib.FrequenciesDifferenceEnglishASCIIScore(canMsg)

        if canScore < bestScore {
            bestScore = canScore
            bestMsg = canMsg
            bestKey = key
        }
    }

    fmt.Println("Challenge 4 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(bestMsg))
    fmt.Printf("Key: %v\n", bestKey)
    fmt.Printf("Candidate Message Score: %v\n", bestScore)
}

/* Below code is all for problem 5. I should start breaking these out into
their own files */

func findCandidateKeysize(input []byte) int {
    // HACK FOR NOW just do 2 to 40
    bestKeysize := 0
    bestHamming := 10000.0
    for keysize := 2; keysize <= 40; keysize++ {
        hamming := cryptolib.AverageBlockHammingDist(input, uint(keysize), 10)

        if hamming < bestHamming {
            bestHamming = hamming
            bestKeysize = keysize
        }
    }

    return bestKeysize
}

func challenge6() {
    // Step 1: Read in the keyfile and decode it from base64
    data, err := ioutil.ReadFile("data/6.txt")
    if err != nil {
        fmt.Printf("ERROR in file read %v\n", err)
        return
    }
    data = cryptolib.DecodeBase64(string(data))

    // Step 2: Find a likely candidate for the keysize
    keysize := findCandidateKeysize(data)

    // Step 3: Create transposed blocks for each byte in the key
    var blocks [][]byte = make([][]byte, keysize)
    for i := 0; i < len(data); i++ {
        blockNum := i % keysize
        // This is possibly memory management hell, I should really alloc the
        // right count at the beginning
        blocks[blockNum] = append(blocks[blockNum], data[i])
    }

    // Step 4: Solve each transposed block as if single-key XOR
    var keys []byte = make([]byte, keysize)
    for i := 0; i < keysize; i++ {
        key, err := cryptolib.CrackSingleByteXor(blocks[i],
            cryptolib.FrequenciesDifferenceEnglishASCIIScore)
        if err != nil {
            fmt.Printf("ERROR: No valid candidate key found for block %v\n", i)
        }
        keys[i] = key
    }

    // Step 5: Output message as decoded with candidate key
    plaintext := cryptolib.DecryptXor(data, keys)
    fmt.Printf("%v\n", string(plaintext))
}

// Main function just runs whatever exercise I'm currently working on
func main() {
    challenge6()
}
