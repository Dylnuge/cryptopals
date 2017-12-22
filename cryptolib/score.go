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


/**
Score a candidate text based only on each individual character.

This is a pretty naive way to do scoring; we assume the data is in ASCII, add
points based on letter frequency, and remove a large number of points for
characters that should never appear (like control characters).

There are numerous flaws in this method; for instance, the string "EEEEEE" would
score higher than "Friend", since "E" is a more frequent letter and therefore
worth more points outright.
*/
func NaiveEnglishASCIIScore(text []byte) float64 {
    var score float64 = 0

    for i := 0; i < len(text); i++ {
        eval_char := text[i]
        if eval_char >= 'A' && eval_char <= 'Z' {
            // Ignore case; convert uppercase characters to lowercase
            eval_char += 32
        }
        if eval_char >= 'a' && eval_char <= 'z' {
            score += EnglishAlphabetFrequencies[eval_char]
        }
    }

    return score;
}
