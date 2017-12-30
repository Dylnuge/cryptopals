package serversim

import (
    "testing"
    "reflect"
)

func TestParseCookie(t *testing.T) {
    cases := []struct {
        in []byte
        expectedCookie map[string]string
        expectedError bool
    }{
        {[]byte("user=dylnuge@example.com&admin=true"), map[string]string{
            "user": "dylnuge@example.com",
            "admin": "true",
        }, false},
        // Currently this method does not decode the URL encoded values
        {[]byte("user=dyl%26an"), map[string]string{
            "user": "dyl%26an",
        }, false},
        {[]byte("user=dylan&admin"), nil, true},
    }

    for _, c := range cases {
        out, err := ParseCookie(c.in)
        if err != nil && !c.expectedError {
            t.Errorf("ParseCookie(%v) produced error %v but expected out %v", c.in, err, c.expectedCookie)
        } else if err == nil && c.expectedError {
            t.Errorf("ParseCookie(%v) == %v but expected to encounter an error", c.in, out)
        } else if !reflect.DeepEqual(out, c.expectedCookie) {
            t.Errorf("ParseCookie(%v) == %v but expected %v", c.in, out, c.expectedCookie)
        }
    }
}
