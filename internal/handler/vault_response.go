package handler

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/service"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Encode metadata separately and stream base64: encoding/json buffers a whole
// value before writing it, which would duplicate an existing large vault blob.
func respondVault(w http.ResponseWriter, r *http.Request, v *service.VaultResponse) {
	if len(v.Blob) == 0 {
		respondJSON(w, http.StatusOK, v)
		return
	}
	middleware.StreamResponse(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Add("Vary", "Accept-Encoding")
	var out io.Writer = w
	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		compressed := gzip.NewWriter(w)
		defer func() {
			if err := compressed.Close(); err != nil {
				log.Error().Err(err).Msg("failed to finish compressed vault response")
			}
		}()
		out = compressed
		w.Header().Set("Content-Encoding", "gzip")
	}
	metadata := *v
	metadata.Blob = nil
	prefix, err := json.Marshal(&metadata)
	if err != nil {
		log.Error().Err(err).Msg("failed to encode vault metadata")
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err = out.Write(prefix[:len(prefix)-1]); err != nil {
		return
	}
	if _, err = io.WriteString(out, `,"blob":"`); err != nil {
		return
	}
	encoder := base64.NewEncoder(base64.StdEncoding, out)
	if _, err = encoder.Write(v.Blob); err != nil {
		return
	}
	if err = encoder.Close(); err != nil {
		return
	}
	_, _ = io.WriteString(out, "\"}\n")
}
func acceptsGzip(value string) bool {
	for _, entry := range strings.Split(value, ",") {
		parts := strings.Split(entry, ";")
		if strings.TrimSpace(parts[0]) != "gzip" {
			continue
		}
		for _, parameter := range parts[1:] {
			name, v, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && name == "q" {
				q, err := strconv.ParseFloat(v, 64)
				return err == nil && q > 0 && q <= 1
			}
		}
		return true
	}
	return false
}
