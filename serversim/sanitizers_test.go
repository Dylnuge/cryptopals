package serversim

import "testing"

func TestURLSanitizeString(t *testing.T) {
    cases := []struct {
        in string
        out string
    }{
        {"Hello", "Hello"},
        {"Hello&admin", "Hello%26admin"},
        {"Hello&admin=true", "Hello%26admin%3Dtrue"},
        {"Hello%26admin", "Hello%2526admin"},
    }

    for _, c := range cases {
        out := URLSanitizeString(c.in)
        if out != c.out {
            t.Errorf("URLSanitizeString(%v) == %v but expected %v", c.in, out, c.out)
        }
    }
}
