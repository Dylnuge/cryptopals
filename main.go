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
    var best_score float64 = 100000;
    var best_key byte;
    var best_msg []byte = make([]byte, len(encoded));

    for i := 0; i <= int(^byte(0)); i++ {
        var can_key []byte = make([]byte, 1);
        var can_msg []byte = make([]byte, len(encoded));
        can_key[0] = byte(i);
        can_msg = cryptolib.DecryptXor(encoded, can_key);
        score := cryptolib.FrequenciesDifferenceEnglishASCIIScore(can_msg);

        // -1 is a rejected string, don't let it be the best
        if score != -1 && score < best_score {
            best_score = score;
            best_msg = can_msg;
            best_key = can_key[0];
        }
    }

    return best_msg, best_score, best_key;
}

func set1_ch3() {
    // And this "real" function isn't a test function at all. I sense a refactor
    // coming in the morning.

    var in string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    var encoded []byte = cryptolib.DecodeHex(in);

    // XORed against a single "character" to me means any byte. I'm not assuming
    // the key is an alphanumeric ASCII code point.
    best_msg, best_score, best_key := decode_single_byte_xor(encoded);

    fmt.Println("Challenge 3 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(best_msg))
    fmt.Printf("Key: %v\n", best_key)
    fmt.Printf("Candidate Message Score: %v\n", best_score)
}

func set1_ch4() {
    data, err := ioutil.ReadFile("data/4.txt");
    if err != nil {
        fmt.Printf("ERROR in file read %v\n", err);
        return;
    }

    data_lines := bytes.Split(data, []byte("\n"));
    best_score := 10000.0;
    var best_msg []byte;
    var best_key byte;
    for i := 0; i < len(data_lines); i++ {
        line := data_lines[i];
        encoded := cryptolib.DecodeHex(string(line))
        can_msg, can_score, can_key := decode_single_byte_xor(encoded);

        if can_score != -1 && can_score < best_score {
            best_score = can_score;
            best_msg = can_msg;
            best_key = can_key;
        }
    }

    fmt.Println("Challenge 4 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(best_msg))
    fmt.Printf("Key: %v\n", best_key)
    fmt.Printf("Candidate Message Score: %v\n", best_score)
}

func main() {
    set1_ch3();
    set1_ch4();
}
