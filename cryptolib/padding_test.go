package cryptolib

import (
    "bytes"
    "testing"
)

func TestPKCS7Padding(t *testing.T) {
    cases := []struct {
        messageIn []byte
        keysize uint
        expect []byte
    }{
        {[]byte("YELLOW SUBMARINE"), 20, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")},
        {[]byte("TEST"), 4, []byte("TEST")},
        {[]byte("HELLO\x00WORLD"), 12, []byte("HELLO\x00WORLD\x01")},
    }

    for _, c := range cases {
        out := PKCS7PadMessage(c.messageIn, c.keysize)
        if !bytes.Equal(out, c.expect) {
            t.Errorf("PKCS7PadMessage(%v, %v) == %v but expected %v", c.messageIn, c.keysize, out, c.expect)
        }
    }
}
