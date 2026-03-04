package teleport

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/rs/zerolog/log"
)

// Handler exposes HTTP endpoints for Teleport cluster management.
type Handler struct {
	service *Service
	audit   *audit.Logger
}

// NewHandler creates a new Teleport HTTP handler.
func NewHandler(service *Service, auditLogger *audit.Logger) *Handler {
	return &Handler{service: service, audit: auditLogger}
}

func (h *Handler) requireUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return uuid.Nil, false
	}
	return userID, true
}

// RegisterCluster handles POST /v1/teleport/clusters
func (h *Handler) RegisterCluster(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	var req RegisterClusterRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cluster, err := h.service.RegisterCluster(r.Context(), userID, req)
	if err != nil {
		log.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to register teleport cluster")
		respondError(w, http.StatusBadRequest, "failed to register cluster")
		return
	}

	h.audit.LogFromRequest(r, audit.CatTeleport, audit.ActClusterRegister).
		Detail("cluster_id", cluster.ID.String()).
		Detail("proxy_addr", cluster.ProxyAddr).
		Send()

	respondJSON(w, http.StatusCreated, cluster)
}

// ListClusters handles GET /v1/teleport/clusters
func (h *Handler) ListClusters(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	clusters, err := h.service.ListClusters(r.Context(), userID)
	if err != nil {
		log.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to list teleport clusters")
		respondError(w, http.StatusInternalServerError, "failed to list clusters")
		return
	}

	if clusters == nil {
		clusters = []Cluster{}
	}

	h.audit.LogFromRequest(r, audit.CatTeleport, audit.ActClusterList).Send()
	respondJSON(w, http.StatusOK, ClusterListResponse{Clusters: clusters})
}

// DeleteCluster handles DELETE /v1/teleport/clusters/{id}
func (h *Handler) DeleteCluster(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid cluster id")
		return
	}

	if err := h.service.DeleteCluster(r.Context(), clusterID, userID); err != nil {
		log.Warn().Err(err).Str("cluster_id", clusterID.String()).Msg("failed to delete teleport cluster")
		respondError(w, http.StatusInternalServerError, "failed to delete cluster")
		return
	}

	h.audit.LogFromRequest(r, audit.CatTeleport, audit.ActClusterDelete).
		Detail("cluster_id", clusterID.String()).
		Send()

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Login handles POST /v1/teleport/clusters/{id}/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid cluster id")
		return
	}

	var req LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.service.Login(r.Context(), userID, clusterID, req); err != nil {
		log.Warn().Err(err).Str("cluster_id", clusterID.String()).Msg("teleport login failed")
		respondError(w, http.StatusUnauthorized, "login failed")
		return
	}

	h.audit.LogFromRequest(r, audit.CatTeleport, audit.ActTeleportLogin).
		Detail("cluster_id", clusterID.String()).
		Send()

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ListNodes handles GET /v1/teleport/clusters/{id}/nodes
func (h *Handler) ListNodes(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid cluster id")
		return
	}

	nodes, err := h.service.ListNodes(r.Context(), userID, clusterID)
	if err != nil {
		log.Warn().Err(err).Str("cluster_id", clusterID.String()).Msg("failed to list teleport nodes")
		respondError(w, http.StatusInternalServerError, "failed to list nodes")
		return
	}

	if nodes == nil {
		nodes = []Node{}
	}

	h.audit.LogFromRequest(r, audit.CatTeleport, audit.ActNodeList).
		Detail("cluster_id", clusterID.String()).
		Detail("count", len(nodes)).
		Send()

	respondJSON(w, http.StatusOK, NodeListResponse{Nodes: nodes})
}

// GenerateCerts handles POST /v1/teleport/clusters/{id}/certs
func (h *Handler) GenerateCerts(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	clusterID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid cluster id")
		return
	}

	var req CertRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	certs, err := h.service.GenerateCerts(r.Context(), userID, clusterID, req)
	if err != nil {
		log.Warn().Err(err).Str("cluster_id", clusterID.String()).Msg("failed to generate teleport certs")
		respondError(w, http.StatusInternalServerError, "failed to generate certificates")
		return
	}

	h.audit.LogFromRequest(r, audit.CatTeleport, audit.ActCertGenerate).
		Detail("cluster_id", clusterID.String()).
		Detail("expires_at", certs.ExpiresAt.String()).
		Send()

	respondJSON(w, http.StatusOK, certs)
}

// --- HTTP helpers (self-contained to avoid import cycle with handler pkg) ---

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Error().Err(err).Msg("failed to encode JSON response")
		}
	}
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func decodeJSON(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}
