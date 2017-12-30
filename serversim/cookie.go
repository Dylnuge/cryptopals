package serversim

import (
    "bytes"
    "errors"
)

func ParseCookie(cookieString []byte) (cookie map[string]string, err error) {
    cookie = map[string]string{}
    cookiePairs := bytes.Split(cookieString, []byte("&"))
    for i := 0; i < len(cookiePairs); i++ {
        splitCookie := bytes.Split(cookiePairs[i], []byte("="))
        if len(splitCookie) != 2 {
            err = errors.New("Malformed cookie")
            cookie = nil
            return
        } else {
            cookie[string(splitCookie[0])] = string(splitCookie[1])
        }
    }
    return
}
