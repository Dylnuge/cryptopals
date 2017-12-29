package cryptolib

/**
Pad a message to be block encrypted with the method defined in PKCS#7

RFC describing algorithm: https://tools.ietf.org/html/rfc2315#section-10.3

To summarize, where a message is expected to be a multiple of some bytes, find
the number of additional bytes of padding that are needed, and pad the message
with that many bytes where each byte of padding contains the number of bytes of
padding being inserted and all bytes are inserted at the end.
*/
func PKCS7PadMessage(message []byte, keysize uint) []byte {
    // Find the number of bytes to pad
    paddingSize := keysize - (uint(len(message)) % keysize)

    // Make the output, initialize it to be a copy of message
    output := make([]byte, uint(len(message)) + paddingSize)
    copy(output, message)

    // Add padding to the output
    for i := uint(0); i < paddingSize; i++ {
        output[uint(len(message)) + i] = byte(paddingSize)
    }

    return output
}
