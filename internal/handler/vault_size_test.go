package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

func TestPutVaultOversizedChunkedRequestReturns413(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	req := authedRequest(httptest.NewRequest(http.MethodPut, "/v1/vault", strings.NewReader(`{"version":1,"blob":"`+strings.Repeat("A", 128)+`","checksum":"test"}`)), uuid.New())
	req.ContentLength = -1
	w := httptest.NewRecorder()
	middleware.BodyLimit(64)(http.HandlerFunc(h.PutVault)).ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d; want 413", w.Code)
	}
}

func TestDecodedVault15MiBBoundaryReturns413BeforePersistence(t *testing.T) {
	for _, size := range []int{15 << 20, (15 << 20) + 1} {
		repo := &mockVaultRepo{}
		logger := audit.NewNopLogger()
		defer logger.Stop(context.Background())
		h := NewVaultHandler(service.NewVaultService(repo, nil, 15, 10), nil, logger)
		blob := make([]byte, size)
		sum := sha256.Sum256(blob)
		body, _ := json.Marshal(service.PutVaultRequest{Version: 1, Blob: blob, Checksum: hex.EncodeToString(sum[:])})
		r := authedRequest(httptest.NewRequest("PUT", "/v1/vault", bytes.NewReader(body)), uuid.New())
		w := httptest.NewRecorder()
		middleware.APIBodyLimit(15<<20)(http.HandlerFunc(h.PutVault)).ServeHTTP(w, r)
		want := 200
		if size > 15<<20 {
			want = 413
		}
		if w.Code != want {
			t.Errorf("decoded size %d returned %d want %d", size, w.Code, want)
		}
		if want == 413 && repo.vault != nil {
			t.Fatal("oversized vault persisted")
		}
	}
}

type vaultCountWriter struct {
	header http.Header
	n      int
}

func (w *vaultCountWriter) Header() http.Header         { return w.header }
func (w *vaultCountWriter) WriteHeader(int)             {}
func (w *vaultCountWriter) Write(b []byte) (int, error) { w.n += len(b); return len(b), nil }
func TestOversizedLegacyVaultReadAvoidsFullJSONBuffer(t *testing.T) {
	blob := make([]byte, 16<<20)
	repo := &mockVaultRepo{vault: &model.Vault{Version: 7, Blob: blob, Checksum: "legacy"}}
	logger := audit.NewNopLogger()
	defer logger.Stop(context.Background())
	svc := service.NewVaultService(repo, nil, 15, 10)
	h := NewVaultHandler(svc, nil, logger)
	if got, err := svc.GetVault(context.Background(), uuid.New()); err != nil || len(got.Blob) != len(blob) {
		t.Fatal("legacy vault became unreadable")
	}
	w := &vaultCountWriter{header: make(http.Header)}
	r := authedRequest(httptest.NewRequest("GET", "/v1/vault", nil), uuid.New())
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	middleware.ResponsePadding(http.HandlerFunc(h.GetVault)).ServeHTTP(w, r)
	runtime.ReadMemStats(&after)
	if w.n < ((len(blob)+2)/3)*4 {
		t.Fatal("legacy vault export truncated")
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 2<<20 {
		t.Errorf("legacy vault read allocated %d bytes; budget 2 MiB beyond existing blob", n)
	}
}

func TestChunkedVaultTrailingOverflowCannotPersist(t *testing.T) {
	repo := &mockVaultRepo{}
	h := newVaultHandler(repo)
	sum := sha256.Sum256([]byte{1})
	body, _ := json.Marshal(service.PutVaultRequest{Version: 1, Blob: []byte{1}, Checksum: hex.EncodeToString(sum[:])})
	req := authedRequest(httptest.NewRequest("PUT", "/v1/vault", strings.NewReader(string(body)+strings.Repeat(" ", 512))), uuid.New())
	req.ContentLength = -1
	w := httptest.NewRecorder()
	middleware.BodyLimit(256)(http.HandlerFunc(h.PutVault)).ServeHTTP(w, req)
	if w.Code != 413 || repo.vault != nil {
		t.Errorf("oversized chunked trailing body persisted: status=%d", w.Code)
	}
}

func TestStreamedVaultGzipAndIdentityRoundTrip(t *testing.T) {
	blob := bytes.Repeat([]byte("opaque vault ciphertext"), 4096)
	for _, encoding := range []string{"gzip", "gzip;q=0"} {
		t.Run(encoding, func(t *testing.T) {
			repo := &mockVaultRepo{vault: &model.Vault{Version: 9, Blob: blob, Checksum: "legacy"}}
			h := NewVaultHandler(service.NewVaultService(repo, nil, 15, 10), nil, audit.NewNopLogger())
			r := authedRequest(httptest.NewRequest("GET", "/v1/vault", nil), uuid.New())
			r.Header.Set("Accept-Encoding", encoding)
			w := httptest.NewRecorder()
			middleware.ResponsePadding(http.HandlerFunc(h.GetVault)).ServeHTTP(w, r)
			var source io.Reader = w.Body
			if encoding == "gzip" {
				if w.Header().Get("Content-Encoding") != "gzip" {
					t.Fatal("gzip not selected")
				}
				z, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer z.Close()
				source = z
			} else if w.Header().Get("Content-Encoding") != "" {
				t.Fatal("gzip selected despite q=0")
			}
			encoded, err := io.ReadAll(source)
			if err != nil {
				t.Fatal(err)
			}
			var got service.VaultResponse
			if err = json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if got.Version != 9 || got.Checksum != "legacy" || !bytes.Equal(got.Blob, blob) {
				t.Fatal("streamed response changed stored vault")
			}
			if w.Header().Get("Content-Length") != "" {
				t.Fatal("streamed response was fully buffered/padded")
			}
		})
	}
}
