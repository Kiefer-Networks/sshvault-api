package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

const paddingBoundary = 1024
const maxPaddedResponse = 64 * 1024

// ResponsePadding normalizes bounded JSON responses only. Larger responses and
// explicitly streamed vault blobs bypass padding without a response-sized copy.
func ResponsePadding(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pw := &paddedWriter{ResponseWriter: w, method: r.Method}
		next.ServeHTTP(pw, r)
		if pw.committed {
			return
		}
		if pw.statusCode == 0 {
			pw.statusCode = http.StatusOK
		}
		body := pw.buf.Bytes()
		if pw.bodyAllowed() && pw.isJSON() && !pw.bypass {
			body = padToKB(body)
		}
		if !pw.bodyAllowed() {
			body = nil
		}
		if pw.statusCode != http.StatusNoContent && pw.statusCode != http.StatusNotModified {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		} else {
			w.Header().Del("Content-Length")
		}
		w.WriteHeader(pw.statusCode)
		if len(body) > 0 {
			_, _ = w.Write(body)
		}
	})
}

type paddedWriter struct {
	http.ResponseWriter
	buf               bytes.Buffer
	statusCode        int
	method            string
	bypass, committed bool
}

func (pw *paddedWriter) Unwrap() http.ResponseWriter { return pw.ResponseWriter }
func (pw *paddedWriter) isJSON() bool {
	return strings.HasPrefix(pw.Header().Get("Content-Type"), "application/json") && pw.Header().Get("Content-Encoding") == ""
}
func (pw *paddedWriter) bodyAllowed() bool {
	return pw.method != http.MethodHead && pw.statusCode != http.StatusNoContent && pw.statusCode != http.StatusNotModified && pw.statusCode >= 200
}
func (pw *paddedWriter) WriteHeader(code int) {
	if pw.committed || pw.statusCode != 0 {
		return
	}
	if code >= 100 && code < 200 {
		pw.ResponseWriter.WriteHeader(code)
		return
	}
	pw.statusCode = code
}
func (pw *paddedWriter) Write(b []byte) (int, error) {
	if pw.statusCode == 0 {
		pw.statusCode = http.StatusOK
	}
	if !pw.bodyAllowed() {
		return len(b), nil
	}
	if pw.committed {
		return pw.ResponseWriter.Write(b)
	}
	if pw.bypass || !pw.isJSON() || len(b) > maxPaddedResponse-pw.buf.Len() {
		if err := pw.stream(); err != nil {
			return 0, err
		}
		return pw.ResponseWriter.Write(b)
	}
	return pw.buf.Write(b)
}
func (pw *paddedWriter) stream() error {
	if pw.committed {
		return nil
	}
	pw.committed = true
	if pw.statusCode == 0 {
		pw.statusCode = http.StatusOK
	}
	pw.ResponseWriter.WriteHeader(pw.statusCode)
	if pw.buf.Len() > 0 {
		_, err := pw.buf.WriteTo(pw.ResponseWriter)
		return err
	}
	return nil
}
func (pw *paddedWriter) FlushError() error {
	if err := pw.stream(); err != nil {
		return err
	}
	return http.NewResponseController(pw.ResponseWriter).Flush()
}
func (pw *paddedWriter) Flush()         { _ = pw.FlushError() }
func (pw *paddedWriter) bypassPadding() { pw.bypass = true }

// StreamResponse marks an opaque response before its first body write. Headers
// still remain mutable until WriteHeader/Write, including gzip negotiation.
func StreamResponse(w http.ResponseWriter) {
	for {
		if p, ok := w.(interface{ bypassPadding() }); ok {
			p.bypassPadding()
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}
func padToKB(data []byte) []byte {
	if n := len(data) % paddingBoundary; n != 0 {
		for range paddingBoundary - n {
			data = append(data, ' ')
		}
	}
	return data
}
