package cryptolib

import "testing"

// Testing where key length is identical to message length
func TestChallenge2(t *testing.T) {
    var in1 string = "1c0111001f010100061a024b53535009181c"
    var in2 string = "686974207468652062756c6c277320657965"
    var expected_out string = "746865206b696420646f6e277420706c6179"

    a := DecodeHex(in1)
    b := DecodeHex(in2)
    var output string = EncodeHex(DecryptXor(a, b))

    if output != expected_out {
        t.Errorf("FAIL Challenge 2\nActual:   %v\nExpected: %v\n",
            output, expected_out)
    }
}

func TestDecryptXorSingleCharKey(t *testing.T) {
    // This problem gets interesting, and forces me to really consider if I want
    // this code to be as wild as it currently is. For now, intermediate test
    // cases, since the problems aren't so trivial that they're solved in one
    // step.
    // TODO(dylan): this is not a challenge it is a test case for DecryptXor
    var in1 string = "123456"
    var in2 string = "01"

    var expected_out string = "133557"

    a := DecodeHex(in1)
    b := DecodeHex(in2)
    var output string = EncodeHex(DecryptXor(a, b))

    if output != expected_out {
        t.Errorf("DecryptXor(%v, %v) == %v but expected %v",
            in1, in2, output, expected_out)
    }
}

func TestRepeatingKeyXor(t *testing.T) {
    var testin string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    var expect string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    out := DecryptXor([]byte(testin), []byte("ICE"))
    out_hex := EncodeHex(out)
    if expect != out_hex {
        t.Errorf("DecryptXor(%v, %v) == %v but expected %v",
            testin, "ICE", out_hex, expect)
    }
}
