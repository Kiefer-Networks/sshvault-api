package middleware

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
)

type countWriter struct {
	header http.Header
	n      int
	status int
}

func (w *countWriter) Header() http.Header         { return w.header }
func (w *countWriter) WriteHeader(s int)           { w.status = s }
func (w *countWriter) Write(b []byte) (int, error) { w.n += len(b); return len(b), nil }
func TestLargeResponsesStreamWithBoundedConcurrentPaddingAllocations(t *testing.T) {
	chunk := make([]byte, 32<<10)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := &countWriter{header: make(http.Header)}
			h := ResponsePadding(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				out.Header().Set("Content-Type", "application/json")
				for i := 0; i < (15<<20)/len(chunk); i++ {
					_, _ = out.Write(chunk)
					if i == 4 && w.n == 0 {
						t.Error("large response still fully buffered")
					}
				}
			}))
			h.ServeHTTP(w, httptest.NewRequest("GET", "/large", nil))
			if w.n != 15<<20 {
				t.Errorf("stream length=%d", w.n)
			}
		}()
	}
	wg.Wait()
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > 8<<20 {
		t.Errorf("four concurrent streams allocated %d bytes; budget 8 MiB", n)
	}
}
