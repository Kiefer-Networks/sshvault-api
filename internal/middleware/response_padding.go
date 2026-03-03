package middleware

import (
	"bytes"
	"fmt"
	"net/http"
)

const paddingBoundary = 1024 // 1 KB

// ResponsePadding pads HTTP responses to the next 1 KB boundary to prevent
// response-size side-channel attacks.
func ResponsePadding(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pw := &paddedWriter{
			ResponseWriter: w,
			buf:            &bytes.Buffer{},
		}
		next.ServeHTTP(pw, r)

		body := pw.buf.Bytes()
		padded := padToKB(body)

		if pw.statusCode == 0 {
			pw.statusCode = http.StatusOK
		}

		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(padded)))
		w.WriteHeader(pw.statusCode)
		_, _ = w.Write(padded)
	})
}

type paddedWriter struct {
	http.ResponseWriter
	buf        *bytes.Buffer
	statusCode int
}

func (pw *paddedWriter) Write(b []byte) (int, error) {
	return pw.buf.Write(b)
}

func (pw *paddedWriter) WriteHeader(code int) {
	pw.statusCode = code
}

// padToKB pads data to the next 1 KB boundary with spaces.
func padToKB(data []byte) []byte {
	n := len(data)
	if n == 0 {
		return data
	}
	remainder := n % paddingBoundary
	if remainder == 0 {
		return data
	}
	padLen := paddingBoundary - remainder
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = ' '
	}
	return append(data, padding...)
}
