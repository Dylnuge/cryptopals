package cryptopals

import "fmt"

/**
DecryptXor applies a simple bitwise XOR to a cyphertext.

Note that despite the name, this could just as easily be used to encrypt XOR.
Reapplying it on the same key will produce the original input, or, in code:
    DecryptXor(DecryptXor(input, key), key) == input

Inputs:
    cyphertext []byte: The cyphertext to decrypt.
    key []byte: The key to XOR the cyphertext against. May be shorter than the
        cyphertext, in which case, repeating key XOR will be assumed.

Outputs:
    out []byte: The result of XORing the cyphertext against the key.
*/
func DecryptXor(cyphertext []byte, key []byte) []byte {
    if len(cyphertext) < len(key) {
        fmt.Println("ERROR raw_xor sanity check failed, key too long");
        return nil;
    }

    xor_len := len(cyphertext)
    out := make([]byte, xor_len);

    for i := 0; i < xor_len; i++ {
        key_pos := i;
        for key_pos >= len(key) {
            key_pos = key_pos - len(key);
        }
        out[i] = cyphertext[i] ^ key[key_pos];
    }

    return out;
}
