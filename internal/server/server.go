// Package server wires the lookup service's HTTP handlers — the
// standard GOBL Net well-known endpoints (inbox / who / keys /
// jwks) plus the public /parties registry record.
package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/identity"
	"github.com/invopop/gobl.lookup/internal/registry"
)

// Sender abstracts the outbound delivery component so handlers
// can be unit-tested without making real HTTP calls.
// (delivery.Sender satisfies this interface.)
type Sender interface {
	Send(ctx context.Context, addr goblnet.Address, env *gobl.Envelope) error
}

// Deps bundles the dependencies handed to NewMux.
type Deps struct {
	// Identity is the lookup's own GOBL Net identity (private
	// signing key, party.json, published JWKs).
	Identity *identity.Identity
	// Registry persists registration records.
	Registry registry.Registrar
	// Client verifies incoming envelopes (FetchKey + crypto).
	Client *goblnet.Client
	// Sender delivers the countersigned envelope back to the
	// subject's /inbox.
	Sender Sender
	// Logger receives all structured access / event log entries.
	Logger *slog.Logger
	// PublicBaseURL is the canonical https URL clients use to
	// fetch this lookup (e.g. "https://lookup.gobl.org"). Used to
	// build the head.Link to the public registration record. May
	// be empty in tests; the link header is then omitted.
	PublicBaseURL string
}

// NewMux constructs the HTTP request multiplexer for the lookup
// service. The returned handler is wrapped in the structured
// access-log middleware.
func NewMux(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	mux := http.NewServeMux()
	self := d.Identity.URI()

	mux.HandleFunc("POST "+goblnet.InboxPath, handleInbox(d, self))
	mux.HandleFunc("POST "+goblnet.WhoPath, handleWho(d, self))
	mux.HandleFunc("GET "+goblnet.KeysPath+"/{kid}", handleKey(d))
	mux.HandleFunc("GET "+goblnet.JWKSPath, handleJWKS(d))
	mux.HandleFunc("GET /parties/{key}", handleParty(d))
	mux.HandleFunc("GET /healthz", handleHealth(d))

	return withAccessLog(d.Logger, mux)
}

// allowedCaller checks the lookup's allow.json against the
// verified caller address. If the allow-list is empty, any caller
// is permitted.
func allowedCaller(id *identity.Identity, caller goblnet.Address) bool {
	if len(id.Allow) == 0 {
		return true
	}
	for _, a := range id.Allow {
		if a == caller {
			return true
		}
	}
	return false
}

// writeJSON writes v as application/json and logs an error on
// serialisation failure.
func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func handleHealth(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []byte(`{"status":"ok"}`))
	}
}

// audMatches reports whether the supplied URI equals the lookup's
// self URI (for /inbox / /who replay-protection).
func audMatches(aud, self cbc.URI) bool {
	return aud != "" && aud == self
}
