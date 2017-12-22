package cryptopals

import (
    "bytes"
    "fmt"
    "io/ioutil"
)

func score_english_ascii(guess []byte) int {
    // Starting with the extremely naive and effectively disqualifying things
    // that use control characters. Numbers are neutral. Alpha characters add.
    var score int = 0;

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
        // TODO this has gotten out of hand just build a map with letter scores
        case eval_char == 'E' || eval_char == 'e':
            score += 12;
        case eval_char == 'T' || eval_char == 't':
            score += 9;
        case eval_char == 'A' || eval_char == 'a':
            score += 8;
        case eval_char == 'O' || eval_char == 'o':
            score += 8;
        case eval_char == 'I' || eval_char == 'i':
            score += 7;
        case eval_char == 'N' || eval_char == 'n':
            score += 7;
        case eval_char == 'S' || eval_char == 's':
            score += 6;
        case eval_char == 'H' || eval_char == 'h':
            score += 6;
        case eval_char == 'R' || eval_char == 'r':
            score += 6;
        case eval_char == 'D' || eval_char == 'd':
            score += 4;
        case eval_char == 'L' || eval_char == 'l':
            score += 4;
        case eval_char == 'C' || eval_char == 'c':
            score += 3;
        case eval_char == 'U' || eval_char == 'u':
            score += 3;
        case eval_char == 'M' || eval_char == 'm':
            score += 2;
        // Remaining letters
        case eval_char >= 'A' && eval_char <= 'Z':
            score += 1;
        case eval_char >= 'a' && eval_char <= 'a':
            score += 1;
        case eval_char == ' ':
            score += 15;
        }
    }

    return score;
}

/* Testing functions for problem set 1

These should probably be pulled out into a unit test file. These are the test
cases provided for each problem set.
*/

func test_set1_ch1() {
    // TODO line lengths come on
    var input string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    var expected_output string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    var data []byte = DecodeHex(input);
    var output string = EncodeBase64(data);

    if output != expected_output {
        fmt.Printf("FAIL Challenge 1\nActual:   %v\nExpected: %v\n", output, expected_output);
    } else {
        fmt.Println("SUCCESS Challenge 1");
    }
}

func test_set1_ch2() {
    var in1 string = "1c0111001f010100061a024b53535009181c";
    var in2 string = "686974207468652062756c6c277320657965";
    var expected_out string = "746865206b696420646f6e277420706c6179";

    a := DecodeHex(in1);
    b := DecodeHex(in2);
    var output string = EncodeHex(DecryptXor(a, b));

    if output != expected_out {
        fmt.Printf("FAIL Challenge 2\nActual:   %v\nExpected: %v\n", output, expected_out);
    } else {
        fmt.Println("SUCCESS Challenge 2");
    }
}

func test_set1_ch3_DecryptXor_func() {
    // This problem gets interesting, and forces me to really consider if I want
    // this code to be as wild as it currently is. For now, intermediate test
    // cases, since the problems aren't so trivial that they're solved in one
    // step.
    // TODO(dylan): this is not a challenge it is a test case for DecryptXor
    var in1 string = "123456"
    var in2 string = "01"

    var expected_out string = "133557";

    a := DecodeHex(in1);
    b := DecodeHex(in2);
    var output string = EncodeHex(DecryptXor(a, b));

    if output != expected_out {
        fmt.Printf("FAIL Challenge 3\nActual:   %v\nExpected: %v\n", output, expected_out);
    } else {
        fmt.Println("PARTIAL Challenge 3");
    }
}

// TODO helper function move it
func decode_single_byte_xor(encoded []byte) ([]byte, int, byte) {
    var best_score int = -100000;
    var best_key byte;
    var best_msg []byte = make([]byte, len(encoded));

    for i := 0; i <= int(^byte(0)); i++ {
        var can_key []byte = make([]byte, 1);
        var can_msg []byte = make([]byte, len(encoded));
        can_key[0] = byte(i);
        can_msg = DecryptXor(encoded, can_key);
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
    var encoded []byte = DecodeHex(in);

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
    best_score := -10000;
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
    test_set1_ch1();
    test_set1_ch2();
    test_set1_ch3_DecryptXor_func();
    test_set1_ch3();
    test_set1_ch4();
}
