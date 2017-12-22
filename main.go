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

func raw_xor(a []byte, b []byte) []byte {
    // Validate a and b are the same length. If they aren't refuse to operate.
    if len(a) != len(b) {
        fmt.Println("ERROR raw_xor sanity check failed, input lengths don't match");
        return nil;
    }

    xor_len := len(a)
    out := make([]byte, xor_len);

    for i := 0; i < xor_len; i++ {
        out[i] = a[i] ^ b[i];
    }

    return out;
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

func main() {
    test_set1_ch1();
    test_set1_ch2();
}
