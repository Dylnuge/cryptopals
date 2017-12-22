package cryptolib

// Frequencies of each letter in the English alphabet.
// There's a neat little citation nest here but I pulled these from Wikipedia
// https://en.wikipedia.org/wiki/Letter_frequency
var EnglishAlphabetFrequencies map[byte]float64 = map[byte]float64{
    'e': 0.12702,
    't': 0.09056,
    'a': 0.08167,
    'o': 0.07507,
    'i': 0.06966,
    'n': 0.06749,
    's': 0.06327,
    'h': 0.06094,
    'r': 0.05987,
    'd': 0.04253,
    'l': 0.04025,
    'c': 0.02782,
    'u': 0.02758,
    'm': 0.02406,
    'w': 0.02360,
    'f': 0.02228,
    'g': 0.02015,
    'y': 0.01974,
    'p': 0.01929,
    'b': 0.01492,
    'v': 0.00978,
    'k': 0.00772,
    'j': 0.00153,
    'x': 0.00150,
    'q': 0.00095,
    'z': 0.00074,
}

// A set of ASCII codepoints that should trigger rejection of a string
var ASCIIAbnormalControlCharacters map[byte]bool = map[byte]bool{
    // 0 is NUL, which may be a string terminator
    1: true, // SOH
    2: true, // STX
    3: true, // ETX
    4: true, // EOT
    5: true, // ENQ
    6: true, // ACK
    7: true, // BEL
    8: true, // BS (shouldn't really be in text)
    // 9 is TAB, which may appear in valid text
    // 10 is LF, which is a line terminator
    11: true, // VT
    12: true, // FF
    // 13 is CR, which is part of CRLF windows-style terminated lines
    14: true, // SO
    15: true, // SI
    16: true, // DLE
    17: true, // DC1
    18: true, // DC2
    19: true, // DC3
    20: true, // DC4
    21: true, // NAK
    22: true, // SYN
    23: true, // ETB
    24: true, // CAN
    25: true, // EM
    26: true, // SUB
    27: true, // ESC
    28: true, // FS
    29: true, // GS
    30: true, // RS
    31: true, // US
    127: true, // DEL (shouldn't really be in text)
}


/**
Score a candidate text based only on each individual character.

This is a pretty naive way to do scoring; we assume the data is in ASCII, add
points based on letter frequency, and remove a large number of points for
characters that should never appear (like control characters).

There are numerous flaws in this method; for instance, the string "EEEEEE" would
score higher than "Friend", since "E" is a more frequent letter and therefore
worth more points outright.

Returns a float score which is 0 if no characters were found, -1 if a rejection
character was found, and otherwise the sum of the frequencies of the letters.
Higher scores indicate a more probable plaintext candidate.
*/
func NaiveEnglishASCIIScore(text []byte) float64 {
    var score float64 = 0

    for i := 0; i < len(text); i++ {
        eval_char := text[i]
        switch{
        // Cases where character is a standard letter
        case eval_char >= 'A' && eval_char <= 'Z':
            eval_char += 32
            score += EnglishAlphabetFrequencies[eval_char]
        case eval_char >= 'a' && eval_char <= 'z':
            score += EnglishAlphabetFrequencies[eval_char]
        case eval_char == ' ':
            // This is a cheap trick, and without it this function is pretty
            // crappy at finding English strings. .16 is (1/6), which comes from
            // the average word length in English being about 5 letters, meaning
            // we'd expect about 1 in every 6 characters to be a space. But, of
            // course, that requires that the plaintext even has spaces to
            // begin with.
            score += .16
        case ASCIIAbnormalControlCharacters[eval_char]:
            // Character is in the set of control characters we're assuming
            // will never show up in a valid plaintext, so short-circut reject
            // this candidate. There are problems with this (see the comment
            // below), and our abnormal character set might be outright wrong.
            return -1;
        case eval_char > 127:
            // Non ASCII codepoint. Short-circut reject this string outright.
            // There are some problems with doing this; attack code needs to be
            // nimble, so this might change later. It's easy to break this
            // exploit by dropping a "corrupted" character into an otherwise
            // valid plaintext, for instance.
            return -1;
        }
    }

    return score;
}
