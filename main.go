package main

import (
    "encoding/base64"
    "encoding/hex"
    "fmt"
)

/* Bytes to Pretty Prints Manipulation Functions

These functions handle conversions between raw byte arrays and printed outputs.
Program internals should always handle data as raw bytes, and use other formats
only for accepting and returning values. in_ functions convert from a pretty
printed format into a byte array. out_ functions convert byte arrays into other
formats.

These will likely be early candidates for putting in their own library. Or just
removing entirely, since they pretty much just wrap the Go encoding library.
*/
func in_hex(hex_str string) []byte {
    out, err := hex.DecodeString(hex_str)
    if err != nil {
        fmt.Printf("ERROR in hex decoding %v\n", err);
        return nil;
    }
    return out;
}

func out_hex(raw []byte) string {
    return hex.EncodeToString(raw);
}

func out_b64(raw []byte) string {
    return base64.StdEncoding.EncodeToString(raw);
}

/* Unsorted functions that clearly will wind up being library functions */

// If we're doing repeating key xor, then b should be the _shorter_ input
func raw_xor(a []byte, b []byte) []byte {
    // Validate a is longer than or equal to the length of b. It would be
    // trivial to just swap them but this is code for me only so fuck it.
    if len(a) < len(b) {
        fmt.Println("ERROR raw_xor sanity check failed, second input is longer");
        return nil;
    }

    xor_len := len(a)
    out := make([]byte, xor_len);

    for i := 0; i < xor_len; i++ {
        bpos := i;
        for bpos >= len(b) {
            bpos = bpos - len(b);
        }
        out[i] = a[i] ^ b[bpos];
    }

    return out;
}

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
        case eval_char >= 'A' && eval_char <= 'Z':
            score += 1;
        case eval_char >= 'a' && eval_char <= 'a':
            score += 1;
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

    var data []byte = in_hex(input);
    var output string = out_b64(data);

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

    a := in_hex(in1);
    b := in_hex(in2);
    var output string = out_hex(raw_xor(a, b));

    if output != expected_out {
        fmt.Printf("FAIL Challenge 2\nActual:   %v\nExpected: %v\n", output, expected_out);
    } else {
        fmt.Println("SUCCESS Challenge 2");
    }
}

func test_set1_ch3_raw_xor_func() {
    // This problem gets interesting, and forces me to really consider if I want
    // this code to be as wild as it currently is. For now, intermediate test
    // cases, since the problems aren't so trivial that they're solved in one
    // step.
    // TODO(dylan): this is not a challenge it is a test case for raw_xor
    var in1 string = "123456"
    var in2 string = "01"

    var expected_out string = "133557";

    a := in_hex(in1);
    b := in_hex(in2);
    var output string = out_hex(raw_xor(a, b));

    if output != expected_out {
        fmt.Printf("FAIL Challenge 3\nActual:   %v\nExpected: %v\n", output, expected_out);
    } else {
        fmt.Println("PARTIAL Challenge 3");
    }
}

func test_set1_ch3() {
    // And this "real" function isn't a test function at all. I sense a refactor
    // coming in the morning.

    var in string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    var encoded []byte = in_hex(in);

    // XORed against a single "character" to me means any byte. I'm not assuming
    // the key is an alphanumeric ASCII code point.
    var best_score int = -100000;
    var best_key byte;
    var best_msg []byte = make([]byte, len(encoded));

    for i := 0; i <= int(^byte(0)); i++ {
        var can_key []byte = make([]byte, 1);
        var can_msg []byte = make([]byte, len(encoded));
        can_key[0] = byte(i);
        can_msg = raw_xor(encoded, can_key);
        score := score_english_ascii(can_msg);

        if score > best_score {
            best_score = score;
            best_msg = can_msg;
            best_key = can_key[0];
        }
    }

    fmt.Println("Challenge 3 decoding completed")
    fmt.Printf("Plaintext: %v\n", string(best_msg))
    fmt.Printf("Key: %v\n", best_key)
    fmt.Printf("Candidate Message Score: %v\n", best_score)
}

func main() {
    test_set1_ch1();
    test_set1_ch2();
    test_set1_ch3_raw_xor_func();
    test_set1_ch3();
}
