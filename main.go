package main

import (
    "bytes"
    "fmt"
    "io/ioutil"
    "github.com/dylnuge/cryptopals/cryptolib"
)

func score_english_ascii(guess []byte) float64 {
    // Starting with the extremely naive and effectively disqualifying things
    // that use control characters. Numbers are neutral. Alpha characters add.
    var score float64 = 0;

    for i := 0; i < len(guess); i++ {
        eval_char := guess[i];
        switch {
        case eval_char > 0 && eval_char < 9:
            // Rare control characters for plaintext. Note that NUL is excluded,
            // though in a realistic plaintext we'd only expect _one_ NUL (if
            // any), and it'd be at the end of the plaintext.
            score -= 100;
        case eval_char > 10 && eval_char < 13:
            // More rare control characters. Explicitly excludes TAB, LF, and
            // CR.
            score -= 100;
        case eval_char > 13 && eval_char < 32:
            // And the rest of the control characters. The separator characters
            // might deserve consideration, but I don't see them a lot.
            score -= 100;
        case eval_char > 127:
            // Non ASCII codepoints
            score -= 100;
        case eval_char == 0 || eval_char == 10 || eval_char == 13:
            // These might appear, but a lot of them should reduce likelihood.
            score -= 5;
        case eval_char >= 35 && eval_char <= 47:
            // These might appear, but a lot of them should reduce likelihood.
            score -= 30;
        case eval_char >= 58 && eval_char <= 62:
            // These might appear, but a lot of them should reduce likelihood.
            score -= 30;
        case eval_char >= 91 && eval_char <= 96:
            // These might appear, but a lot of them should reduce likelihood.
            score -= 30;
        case eval_char >= 123 && eval_char <= 127:
            // These might appear, but a lot of them should reduce likelihood.
            score -= 30;
        case eval_char >= '0' && eval_char <= '9':
            score -= 10;
        // Common letters
        case eval_char == ' ':
            score += 1;
        default:
            eval_arr := make([]byte, 1)
            eval_arr[0] = eval_char
            score += cryptolib.NaiveEnglishASCIIScore(eval_arr)
        }
    }

    return score;
}

/* Testing functions for problem set 1

These should probably be pulled out into a unit test file. These are the test
cases provided for each problem set.
*/


// TODO helper function move it
func decode_single_byte_xor(encoded []byte) ([]byte, float64, byte) {
    var best_score float64 = -100000;
    var best_key byte;
    var best_msg []byte = make([]byte, len(encoded));

    for i := 0; i <= int(^byte(0)); i++ {
        var can_key []byte = make([]byte, 1);
        var can_msg []byte = make([]byte, len(encoded));
        can_key[0] = byte(i);
        can_msg = cryptolib.DecryptXor(encoded, can_key);
        score := score_english_ascii(can_msg);

        if score > best_score {
            best_score = score;
            best_msg = can_msg;
            best_key = can_key[0];
        }
    }

    return best_msg, best_score, best_key;
}

func test_set1_ch3() {
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

func test_set1_ch4() {
    data, err := ioutil.ReadFile("data/4.txt");
    if err != nil {
        fmt.Printf("ERROR in file read %v\n", err);
        return;
    }

    data_lines := bytes.Split(data, []byte("\n"));
    best_score := -10000.0;
    var best_msg []byte;
    var best_key byte;
    for i := 0; i < len(data_lines); i++ {
        line := data_lines[i];
        can_msg, can_score, can_key := decode_single_byte_xor(line);

        if can_score > best_score {
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
    test_set1_ch3();
    test_set1_ch4();
}
