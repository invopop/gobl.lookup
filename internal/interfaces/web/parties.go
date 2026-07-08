package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.lookup/internal/domain"
)

// handleParty serves the public registry record at `/parties/<key>`.
// `<key>` may be either an address (FQDN form, e.g. `alice.example`)
// or an envelope UUID. Returns the countersigned envelope as
// application/json on success, 404 when no record matches.
func handleParty(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		if key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		rec, err := s.Registrations().Find(r.Context(), key)
		if errors.Is(err, domain.ErrNotFound) {
			log.Info("party.lookup", "key", key, "found", false)
			http.Error(w, "party not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Error("party.lookup_failed", "key", key, "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if rec.CountersignedEnvelope == nil {
			// Record exists but no countersigned envelope yet
			// (StatusReceived). Treat as not yet published.
			log.Info("party.lookup", "key", key, "found", false, "status", string(rec.Status))
			http.Error(w, "party record not yet published", http.StatusNotFound)
			return
		}
		body, err := json.Marshal(rec.CountersignedEnvelope)
		if err != nil {
			log.Error("party.encode_failed", "key", key, "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Info("party.lookup", "key", key, "found", true)
		writeJSON(w, http.StatusOK, body)
	}
}
