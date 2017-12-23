package cryptolib

import (
    "errors"
    "fmt"
)

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
        fmt.Println("ERROR rawXor sanity check failed, key too long")
        return nil
    }

    xorLen := len(cyphertext)
    out := make([]byte, xorLen)

    for i := 0; i < xorLen; i++ {
        keyPos := i
        for keyPos >= len(key) {
            keyPos = keyPos - len(key)
        }
        out[i] = cyphertext[i] ^ key[keyPos]
    }

    return out
}

/**
Find the single byte key a string has been XORed against.

Given a scoring function to determine how likely a key is to be correct and a
cyphertext that is assumed to have been XORed against a single byte, finds the
most likely key.

Inputs:
    cyphertext []byte: The cyphertext to decrypt.
    scoreFunc func([]byte) (float64, error): A scoring function where lower
        numers are considered better scores. First return value should be the
        score, second should be an optional error which, if present, indicates
        the score should be rejected.

Outputs:
    key byte: The key the string has probably been XORed against
    err error: Returns an error if no possible keys were found
*/
func CrackSingleByteXor(cyphertext []byte,
        scoreFunc func([]byte) (float64, error)) (key byte, err error) {
    var score *float64

    // Loop through every possible 1-byte key
    for i:= 0; i <= int(^byte(0)); i++ {
        candidateKey := []byte{byte(i)}
        candidatePlaintext := DecryptXor(cyphertext, candidateKey)
        candidateScore, scoreErr := scoreFunc(candidatePlaintext)

        if scoreErr != nil {
            // This key doesn't decode properly, and is invalid
            continue
        }

        if score == nil || candidateScore < *score{
            score = &candidateScore
            key = candidateKey[0]
        }
    }

    if score == nil {
        err = errors.New("No valid candidate keys found")
    }

    return
}
