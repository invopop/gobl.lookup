package web

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.lookup/internal/domain"
)

// handleInbox processes a registration request: a signed envelope
// containing the sender's org.Party POSTed to lookup's inbox. The
// handler parses the envelope and delegates to the domain, which
// verifies, countersigns, persists, and queues asynchronous delivery
// back to the sender's /inbox — so the handler can return 202 as soon
// as the record is persisted.
func handleInbox(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, inboxMaxBody)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				log.Warn("inbox.rejected", "reason", "body_too_large", "remote", r.RemoteAddr)
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			log.Warn("inbox.rejected", "reason", "read_body", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "could not read body", http.StatusBadRequest)
			return
		}
		env := new(gobl.Envelope)
		if err := json.Unmarshal(body, env); err != nil {
			log.Warn("inbox.rejected", "reason", "bad_body", "remote", r.RemoteAddr)
			http.Error(w, "invalid envelope JSON", http.StatusBadRequest)
			return
		}
		if _, err := s.Registrations().Register(r.Context(), env); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}
