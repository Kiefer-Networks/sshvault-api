package teleport

import (
	"net/http"

	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/rs/zerolog/log"
)

// RequireTeleportUnlocked is middleware that checks whether the authenticated
// user has purchased the Teleport addon. Returns 403 if not unlocked.
func RequireTeleportUnlocked(repo Repository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := middleware.GetUserID(r.Context())
			if !ok {
				respondError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			unlocked, err := repo.IsTeleportUnlocked(r.Context(), userID)
			if err != nil {
				log.Error().Err(err).Str("user_id", userID.String()).Msg("failed to check teleport_unlocked")
				respondError(w, http.StatusInternalServerError, "internal error")
				return
			}

			if !unlocked {
				respondError(w, http.StatusForbidden, "teleport addon not purchased")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
