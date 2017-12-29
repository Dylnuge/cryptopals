package serversim

var URLSanitizationCharacterMap map[byte]string = map[byte]string {
    // TODO look these up when back online, missing a lot for sure
    '&': "%26",
    ' ': "%20",
    '=': "%3D",
    '/': "%2F",
    '\\': "%5C",
    '"': "%22",
    '%': "%25",
}

/**
Toy URL string sanitizer. Not safe for production usage.

Strips out &, =, and / characters from an input string and replaces them with
the appropriate URL encoding
*/
func URLSanitizeString(unsafe string) string {
    output := ""
    for i := 0; i < len(unsafe); i++ {
        nextChar := unsafe[i]
        if URLSanitizationCharacterMap[nextChar] != "" {
            output += URLSanitizationCharacterMap[nextChar]
        } else {
            output += string(nextChar)
        }
    }
    return output
}
