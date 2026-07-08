package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.lookup/internal/domain"
)

// handleWho implements the authenticated mutual party exchange: the
// caller POSTs a signed envelope (iss=caller, aud=lookup); the domain
// verifies it, applies the allow-list, and returns the lookup's own
// party envelope signed with iss/aud reversed.
func handleWho(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, inboxMaxBody))
		if err != nil {
			log.Warn("who.rejected", "reason", "read_body", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "could not read body", http.StatusBadRequest)
			return
		}
		env := new(gobl.Envelope)
		if err := json.Unmarshal(body, env); err != nil {
			log.Warn("who.rejected", "reason", "bad_body", "remote", r.RemoteAddr)
			http.Error(w, "invalid envelope JSON", http.StatusBadRequest)
			return
		}
		out, err := s.Identity().Exchange(r.Context(), env)
		if err != nil {
			writeError(w, err)
			return
		}
		resp, err := json.Marshal(out)
		if err != nil {
			log.Error("who.encode_failed", "error", err.Error())
			http.Error(w, "could not encode response", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
