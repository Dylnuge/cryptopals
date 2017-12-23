package cryptolib

import (
    "fmt"
    "encoding/base64"
    "encoding/hex"
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
func DecodeHex(hexStr string) []byte {
    out, err := hex.DecodeString(hexStr)
    if err != nil {
        fmt.Printf("ERROR in hex decoding %v\n", err)
        return nil
    }
    return out
}

func EncodeHex(raw []byte) string {
    return hex.EncodeToString(raw)
}

func DecodeBase64(b64Str string) []byte {
    out, err := base64.StdEncoding.DecodeString(b64Str)
    if err != nil {
        fmt.Printf("ERROR in hex decoding %v\n", err)
        return nil
    }
    return out
}

func EncodeBase64(raw []byte) string {
    return base64.StdEncoding.EncodeToString(raw)
}
