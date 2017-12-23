package cryptolib

import "testing"

func TestHammingDist(t *testing.T) {
    in1 := "this is a test"
    in2 := "wokka wokka!!!"
    expect := 37
    out := HammingDist([]byte(in1), []byte(in2))

    if  out != expect {
        t.Errorf("HammingDist(%v, %v) == %v, expected %v\n",
            in1, in2, out, expect)
    }
}
