package server

import (
	"encoding/json"
	"errors"
	"net/http"

	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/registry"
)

// handleParty serves the public registry record at
// `/parties/<key>`. `<key>` may be either an address (FQDN form,
// e.g. `alice.example`) or an envelope UUID. Returns the
// countersigned envelope as application/json on success, 404 when
// no record matches.
func handleParty(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		if key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		rec, err := lookupRecord(r, d, key)
		if errors.Is(err, registry.ErrNotFound) {
			d.Logger.Info("party.lookup", "key", key, "found", false)
			http.Error(w, "party not found", http.StatusNotFound)
			return
		}
		if err != nil {
			d.Logger.Error("party.lookup_failed", "key", key, "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if rec.CountersignedEnvelope == nil {
			// Record exists but no countersigned envelope yet
			// (StatusReceived). Treat as not yet published.
			d.Logger.Info("party.lookup", "key", key, "found", false, "status", string(rec.Status))
			http.Error(w, "party record not yet published", http.StatusNotFound)
			return
		}
		body, err := json.Marshal(rec.CountersignedEnvelope)
		if err != nil {
			d.Logger.Error("party.encode_failed", "key", key, "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		d.Logger.Info("party.lookup", "key", key, "found", true)
		writeJSON(w, http.StatusOK, body)
	}
}

// lookupRecord resolves a path key either as an envelope UUID or
// as a GOBL Net address. The path syntax is overloaded
// deliberately — operators can deep-link by UUID (immutable
// reference from the head.Link) or by human-readable address.
func lookupRecord(r *http.Request, d Deps, key string) (*registry.Record, error) {
	if id, err := uuid.Parse(key); err == nil {
		return d.Registry.GetByUUID(r.Context(), id)
	}
	addr, err := goblnet.ParseAddress(key)
	if err != nil {
		return nil, registry.ErrNotFound
	}
	return d.Registry.Get(r.Context(), addr)
}
