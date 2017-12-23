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


// TODO helper function move it
func decode_single_byte_xor(encoded []byte) ([]byte, float64, byte) {
    var best_score float64 = 100000
    var best_key byte
    var best_msg []byte = make([]byte, len(encoded))

    for i := 0; i <= int(^byte(0)); i++ {
        var can_key []byte = make([]byte, 1)
        var can_msg []byte = make([]byte, len(encoded))
        can_key[0] = byte(i)
        can_msg = cryptolib.DecryptXor(encoded, can_key)
        score := cryptolib.FrequenciesDifferenceEnglishASCIIScore(can_msg)

        // -1 is a rejected string, don't let it be the best
        if score != -1 && score < best_score {
            best_score = score
            best_msg = can_msg
            best_key = can_key[0]
        }
    }

    return best_msg, best_score, best_key
}

func set1_ch3() {
    // And this "real" function isn't a test function at all. I sense a refactor
    // coming in the morning.

    var in string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    var encoded []byte = cryptolib.DecodeHex(in)

    // XORed against a single "character" to me means any byte. I'm not assuming
    // the key is an alphanumeric ASCII code point.
    best_msg, best_score, best_key := decode_single_byte_xor(encoded)

    fmt.Println("Challenge 3 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(best_msg))
    fmt.Printf("Key: %v\n", best_key)
    fmt.Printf("Candidate Message Score: %v\n", best_score)
}

func set1_ch4() {
    data, err := ioutil.ReadFile("data/4.txt")
    if err != nil {
        fmt.Printf("ERROR in file read %v\n", err)
        return
    }

    data_lines := bytes.Split(data, []byte("\n"))
    best_score := 10000.0
    var best_msg []byte
    var best_key byte
    for i := 0; i < len(data_lines); i++ {
        line := data_lines[i]
        encoded := cryptolib.DecodeHex(string(line))
        can_msg, can_score, can_key := decode_single_byte_xor(encoded)

        if can_score != -1 && can_score < best_score {
            best_score = can_score
            best_msg = can_msg
            best_key = can_key
        }
    }

    fmt.Println("Challenge 4 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(best_msg))
    fmt.Printf("Key: %v\n", best_key)
    fmt.Printf("Candidate Message Score: %v\n", best_score)
}

/* Below code is all for problem 5. I should start breaking these out into
their own files */

func find_candidate_keysize(input []byte) int {
    // HACK FOR NOW just do 2 to 40
    best_keysize := 0
    best_hamming := 10000.0
    for keysize := 2; keysize <= 40; keysize++ {
        hamming := cryptolib.AverageBlockHammingDist(input, uint(keysize), 10)

        if hamming < best_hamming {
            best_hamming = hamming
            best_keysize = keysize
        }
    }

    return best_keysize
}

func solve_ch6() {
    // Step 1: Read in the keyfile and decode it from base64
    data, err := ioutil.ReadFile("data/6.txt")
    if err != nil {
        fmt.Printf("ERROR in file read %v\n", err)
        return
    }
    data = cryptolib.DecodeBase64(string(data))

    // Step 2: Find a likely candidate for the keysize
    keysize := find_candidate_keysize(data)

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
        _, _, key := decode_single_byte_xor(blocks[i])
        keys[i] = key
    }

    // Step 5: Output message as decoded with candidate key
    plaintext := cryptolib.DecryptXor(data, keys)
    fmt.Printf("%v\n", string(plaintext))
}

// Main function just runs whatever exercise I'm currently working on
func main() {
    solve_ch6()
}
