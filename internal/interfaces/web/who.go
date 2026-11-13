package web

import (
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.lookup/internal/domain"
)

// whoCacheControl allows the authenticated caller to cache its party
// envelope briefly; the response is signed for the requester so it
// must not land in shared caches. The TTL bounds how quickly key or
// party changes are observed by verifiers.
const whoCacheControl = "private, max-age=300"

// handleWho serves the lookup's identity to an authenticated
// requester: the party envelope from the lookup to the requester,
// signed for it.
func handleWho(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := s.Identity().PartyEnvelope(requesterFrom(r.Context()))
		if err != nil {
			log.Error("who.sign_failed", "error", err.Error())
			http.Error(w, "could not prepare identity", http.StatusInternalServerError)
			return
		}
		log.Info("who.served", "requester", string(requesterFrom(r.Context())))
		w.Header().Set("Cache-Control", whoCacheControl)
		writeJSON(w, http.StatusOK, body)
	}
}
