package cryptopals

import (
    "bytes"
    "testing"
)

func TestDecodeHex(t *testing.T) {
    cases := []struct {
        in string
        expect []byte
    }{
        {"10200a0b", []byte("\x10\x20\x0a\x0b")},
    }

    for _, c := range cases {
        out := DecodeHex(c.in)
        if !bytes.Equal(out, c.expect) {
            t.Errorf("DecodeHex(%v) == %v but expected %v", c.in, out, c.expect)
        }
    }
}

// Keeping around the early challenges as test cases. Not really a unit test,
// but useful since these functions are simple to verify that refactoring didn't
// leave any loose wires.
func TestChallenge1(t *testing.T) {
    var input string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    var expected_output string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    var data []byte = DecodeHex(input);
    var output string = EncodeBase64(data);

    if output != expected_output {
        t.Errorf("FAIL Challenge 1\nActual:   %v\nExpected: %v\n",
            output, expected_output);
    }
}
