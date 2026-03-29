package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
)

var validCategories = map[string]bool{
	string(audit.CatAuth):   true,
	string(audit.CatVault):  true,
	string(audit.CatDevice): true,
	string(audit.CatUser):   true,
	string(audit.CatSystem): true,
}

var validActions = map[string]bool{
	string(audit.ActRegister):       true,
	string(audit.ActLogin):          true,
	string(audit.ActLoginFailed):    true,
	string(audit.ActRefreshToken):   true,
	string(audit.ActLogout):         true,
	string(audit.ActLogoutAll):      true,
	string(audit.ActVerifyEmail):    true,
	string(audit.ActForgotPassword): true,
	string(audit.ActResetPassword):  true,
	string(audit.ActSyncPull):       true,
	string(audit.ActSyncPush):       true,
	string(audit.ActHistoryView):    true,
	string(audit.ActProfileView):    true,
	string(audit.ActProfileUpdate):  true,
	string(audit.ActPasswordChange): true,
	string(audit.ActAccountDelete):  true,
	string(audit.ActDeviceRegister): true,
	string(audit.ActDeviceList):     true,
	string(audit.ActDeviceDelete):   true,
	string(audit.ActStartup):        true,
	string(audit.ActShutdown):       true,
}

type AuditHandler struct {
	repo *audit.Repository
}

func NewAuditHandler(repo *audit.Repository) *AuditHandler {
	return &AuditHandler{repo: repo}
}

func (h *AuditHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	filter := audit.QueryFilter{
		ActorID: &userID,
	}

	if cat := r.URL.Query().Get("category"); cat != "" {
		if !validCategories[cat] {
			respondError(w, http.StatusBadRequest, "invalid audit category")
			return
		}
		filter.Category = cat
	}
	if act := r.URL.Query().Get("action"); act != "" {
		if !validActions[act] {
			respondError(w, http.StatusBadRequest, "invalid audit action")
			return
		}
		filter.Action = act
	}
	if from := r.URL.Query().Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid 'from' format, use RFC3339")
			return
		}
		filter.From = &t
	}
	if to := r.URL.Query().Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid 'to' format, use RFC3339")
			return
		}
		filter.To = &t
	}
	if lim := r.URL.Query().Get("limit"); lim != "" {
		n, err := strconv.Atoi(lim)
		if err != nil || n < 1 {
			respondError(w, http.StatusBadRequest, "invalid 'limit'")
			return
		}
		filter.Limit = n
	}
	if off := r.URL.Query().Get("offset"); off != "" {
		n, err := strconv.Atoi(off)
		if err != nil || n < 0 {
			respondError(w, http.StatusBadRequest, "invalid 'offset'")
			return
		}
		filter.Offset = n
	}

	result, err := h.repo.Query(r.Context(), filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to query audit logs")
		return
	}

	respondJSON(w, http.StatusOK, result)
}
