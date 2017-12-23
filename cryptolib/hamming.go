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

func AverageBlockHammingDist(text []byte, blockSize, blockCount uint) float64 {
    hamming := 0.0
    for i := uint(0); i < blockCount; i++ {
        // Get the i-th and i+1th block of `blockSize` bytes
        slice1 := text[blockSize*i:blockSize*(i+1)]
        slice2 := text[blockSize*(i+1):blockSize*(i+2)]
        hamming += NormalizedHammingDist(slice1, slice2)
    }
    hamming = hamming / float64(blockCount)
    return hamming
}
