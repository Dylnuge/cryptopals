package cryptolib

import "errors"

// Frequencies of each letter in the English alphabet.
// There's a neat little citation nest here but I pulled these from Wikipedia
// https://en.wikipedia.org/wiki/Letter_frequency
var EnglishAlphabetFrequencies map[byte]float64 = map[byte]float64{
    // These don't add to 100% because of this line, but it works well enough
    // for scoring for now.
    ' ': 0.16000, // Finding an actual citation for space frequency is hard...
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

Returns a float score which is the negative sum of the frequencies of the
encountered characters. Lower scores indicate a more probable plaintext
candidate.
*/
func NaiveEnglishASCIIScore(text []byte) (float64, error) {
    var score float64 = 0

    for i := 0; i < len(text); i++ {
        evalChar := text[i]
        switch{
        // Cases where character is a standard letter
        case evalChar >= 'A' && evalChar <= 'Z':
            evalChar += 32
            score -= EnglishAlphabetFrequencies[evalChar]
        case evalChar >= 'a' && evalChar <= 'z':
            score -= EnglishAlphabetFrequencies[evalChar]
        case evalChar == ' ':
            // This is a cheap trick, and without it this function is pretty
            // crappy at finding English strings. .16 is (1/6), which comes from
            // the average word length in English being about 5 letters, meaning
            // we'd expect about 1 in every 6 characters to be a space. But, of
            // course, that requires that the plaintext even has spaces to
            // begin with.
            score -= .16
        case ASCIIAbnormalControlCharacters[evalChar]:
            // Character is in the set of control characters we're assuming
            // will never show up in a valid plaintext, so short-circut reject
            // this candidate. There are problems with this (see the comment
            // below), and our abnormal character set might be outright wrong.
            return 0, errors.New("String has unexpected control characters")
        case evalChar > 127:
            // Non ASCII codepoint. Short-circut reject this string outright.
            // There are some problems with doing this; attack code needs to be
            // nimble, so this might change later. It's easy to break this
            // exploit by dropping a "corrupted" character into an otherwise
            // valid plaintext, for instance.
            return 0, errors.New("String has non-ASCII codepoints")
        }
    }

    return score, nil
}


/**
Score candidate text based on how close its frequencies map to expectations.

Basically, build a map of all the letters we find, compute how frequent those
letters were in the candidate text, compare it against the cannonical frequency
map. We'll include characters that aren't in the map in the denominator but not
the numerator unless those characters are spaces; this is a hack, and I should
really build a frequency map that includes spaces and punctuation.

Since this is a difference function, lower values are better; 0.0 indicates
a perfect match with expected frequencies (highly unlikely). This is hacky and
annoying on two levels: the other scoring function is higher-better, and -1 is
still a special case for a rejected candidate text, since negative outputs aren't
possible.

The naïve function is so clearly worse than this that I might just delete it,
though.
*/
func FrequenciesDifferenceEnglishASCIIScore(text []byte) (float64, error) {
    var score float64 = 0

    candidateCount := map[byte]int{}

    // Sanity check, if we have an empty string, stop and reject
    if len(text) == 0 {
        return 0, errors.New("Text is empty")
    }

    // Build a map from letters to their counts in the string
    for i:= 0; i < len(text); i++ {
        evalChar := text[i]
        // If the character is in our rejection set, reject it
        if ASCIIAbnormalControlCharacters[evalChar] || evalChar > 127 {
            return 0, errors.New("Unexpected or non-ASCII characters")
        }
        // Convert uppercase letters to lowercase letters
        if evalChar >= 'A' && evalChar <= 'Z' {
            evalChar += 32
        }
        // Map lowercase letters into the frequency chart
        if (evalChar >= 'a' && evalChar <= 'z') || (evalChar == ' ') {
            candidateCount[evalChar] += 1
        } else {
            // Count everything else where "NUL" would go
            candidateCount['\x00'] += 1
        }
    }


    // For each English letter, compute square difference from expected
    // frequency and add it to the score
    for i := 0; i < 26; i++ {
        var letter byte = 'a' + byte(i)
        // As a go novitiate, I feel compelled to note that if the letter
        // was never found, the map returns the default empty value, which
        // happens to be 0 for numeric types. Experienced go coders probably
        // didn't even blink at this line but it sure scares me.
        freq := float64(candidateCount[letter]) / float64(len(text))
        expectedFreq := EnglishAlphabetFrequencies[letter]
        squareDiff := (freq - expectedFreq) * (freq - expectedFreq)
        score += squareDiff
    }

    // Add in the space (TODO dylan make this code cleaner)
    var space byte = ' '
    freq := float64(candidateCount[space]) / float64(len(text))
    expectedFreq := EnglishAlphabetFrequencies[space]
    squareDiff := (freq - expectedFreq) * (freq - expectedFreq)
    score += squareDiff

    // And the error from non-matched characters (who we assume we'll see few
    // if any of), again TODO to clean this up
    nullFreq := float64(candidateCount['\x00']) / float64(len(text))
    nullSquareDiff := nullFreq * nullFreq
    score += nullSquareDiff

    return score, nil
}
