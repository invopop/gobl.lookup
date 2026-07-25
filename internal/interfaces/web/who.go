package web

import (
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.lookup/internal/domain"
)

// whoCacheControl allows clients to cache the static party envelope
// briefly; the TTL bounds how quickly key or party changes are
// observed by verifiers.
const whoCacheControl = "public, max-age=300"

// handleWho serves the lookup's public identity: the party envelope
// self-signed by the lookup, the same static document for every
// caller.
func handleWho(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := s.Identity().PartyEnvelope()
		if err != nil {
			log.Error("who.sign_failed", "error", err.Error())
			http.Error(w, "could not prepare identity", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", whoCacheControl)
		writeJSON(w, http.StatusOK, body)
	}
}
