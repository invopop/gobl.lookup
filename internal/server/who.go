package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/head"
)

// handleWho implements the authenticated mutual party exchange:
// the caller POSTs a signed envelope (iss=caller, aud=lookup); the
// lookup verifies it, applies the allow-list, and responds with
// its own party envelope signed with iss/aud reversed.
func handleWho(d Deps, self cbc.URI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, inboxMaxBody))
		if err != nil {
			d.Logger.Warn("who.rejected", "reason", "read_body", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "could not read body", http.StatusBadRequest)
			return
		}
		req := new(gobl.Envelope)
		if err := json.Unmarshal(body, req); err != nil {
			d.Logger.Warn("who.rejected", "reason", "bad_body", "remote", r.RemoteAddr)
			http.Error(w, "invalid envelope JSON", http.StatusBadRequest)
			return
		}
		caller, err := d.Client.VerifyEnvelope(r.Context(), req, self)
		if err != nil {
			d.Logger.Warn("who.rejected", "reason", "verify_failed", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		// Also require an explicit aud match; VerifyEnvelope's
		// expectedAud check is the same, but `inbox` tightening
		// taught us to make this explicit so the log carries the
		// right reason.
		p, err := head.SignedPayload(req.Signatures[0])
		if err != nil || p.Aud != self {
			d.Logger.Warn("who.rejected", "reason", "aud_mismatch", "caller", string(caller))
			http.Error(w, "envelope audience does not match this lookup", http.StatusUnauthorized)
			return
		}
		if !allowedCaller(d.Identity, caller) {
			d.Logger.Warn("who.rejected", "reason", "not_allowed", "caller", string(caller))
			http.Error(w, "caller not accepted", http.StatusForbidden)
			return
		}
		env, err := d.Identity.PartyEnvelope(caller.URI())
		if err != nil {
			d.Logger.Error("who.sign_failed", "caller", string(caller), "error", err.Error())
			http.Error(w, "could not sign party envelope", http.StatusInternalServerError)
			return
		}
		out, err := json.Marshal(env)
		if err != nil {
			d.Logger.Error("who.encode_failed", "caller", string(caller), "error", err.Error())
			http.Error(w, "could not encode response", http.StatusInternalServerError)
			return
		}
		d.Logger.Info("who.exchange", "caller", string(caller))
		writeJSON(w, http.StatusOK, out)
	}
}
