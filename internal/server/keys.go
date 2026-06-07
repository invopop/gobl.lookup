package server

import (
	"encoding/json"
	"net/http"
)

func handleKey(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kid := r.PathValue("kid")
		key := d.Identity.FindKey(kid)
		if key == nil {
			d.Logger.Info("keys.lookup", "kid", kid, "found", false)
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		body, err := json.Marshal(key)
		if err != nil {
			d.Logger.Error("keys.lookup_failed", "kid", kid, "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		d.Logger.Info("keys.lookup", "kid", kid, "found", true)
		writeJSON(w, http.StatusOK, body)
	}
}

func handleJWKS(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := d.Identity.JWKS()
		if err != nil {
			d.Logger.Error("jwks.served_failed", "error", err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		d.Logger.Info("jwks.served", "count", len(d.Identity.PublicKeys))
		writeJSON(w, http.StatusOK, body)
	}
}
