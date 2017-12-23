package cryptolib

func HammingDist(a []byte, b []byte) int {
    // For right now, leave the hamming distance of two byte arrays of differing
    // length undefined (we might also define each "additional" bit in the
    // longer string as differing and add to the hamming total)
    if len(a) != len(b) {
        // TODO this isn't C I should follow go's error handling conventions
        return -1
    }

    hammingTotal := 0

    for byte_idx := 0; byte_idx < len(a); byte_idx++ {
        for bit_idx := uint(0); bit_idx < 8; bit_idx++ {
            mask := byte(1 << bit_idx)
            if (a[byte_idx] & mask) != (b[byte_idx] & mask) {
                hammingTotal += 1
            }
        }
    }
    return hammingTotal
}

// Hamming distance divided by bytesize
func NormalizedHammingDist(a []byte, b []byte) float64 {
    hamming := HammingDist(a, b)
    if hamming == -1 {
        return -1
    }
    return float64(hamming) / float64(len(a))
}
