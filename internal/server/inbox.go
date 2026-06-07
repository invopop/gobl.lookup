package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.lookup/internal/identity"
	"github.com/invopop/gobl.lookup/internal/registry"
)

const inboxMaxBody = 1 << 20 // 1 MiB

// handleInbox processes a registration request: a signed envelope
// containing the sender's org.Party POSTed to lookup's inbox. The
// handler returns 202 once the envelope is persisted and the
// Authority countersignature is queued for delivery. The actual
// POST to the sender's /inbox happens asynchronously so the
// caller is not blocked on a downstream RTT.
func handleInbox(d Deps, self cbc.URI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, inboxMaxBody))
		if err != nil {
			d.Logger.Warn("inbox.rejected", "reason", "read_body", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "could not read body", http.StatusBadRequest)
			return
		}
		env := new(gobl.Envelope)
		if err := json.Unmarshal(body, env); err != nil {
			d.Logger.Warn("inbox.rejected", "reason", "bad_body", "remote", r.RemoteAddr)
			http.Error(w, "invalid envelope JSON", http.StatusBadRequest)
			return
		}
		if err := env.Validate(); err != nil {
			d.Logger.Warn("inbox.rejected", "reason", "validation", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "envelope failed validation: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}

		sender, err := d.Client.VerifyEnvelope(r.Context(), env, "")
		if err != nil {
			d.Logger.Warn("inbox.rejected", "reason", "verify_failed", "remote", r.RemoteAddr, "error", err.Error())
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		// Replay protection: signed aud MUST equal this lookup.
		p, perr := head.SignedPayload(env.Signatures[0])
		if perr != nil {
			d.Logger.Warn("inbox.rejected", "reason", "verify_failed", "caller", string(sender), "error", perr.Error())
			http.Error(w, "could not read signed payload", http.StatusUnauthorized)
			return
		}
		if p.Aud == "" {
			d.Logger.Warn("inbox.rejected", "reason", "aud_missing", "caller", string(sender))
			http.Error(w, "envelope must carry an aud equal to this lookup", http.StatusUnauthorized)
			return
		}
		if !audMatches(p.Aud, self) {
			d.Logger.Warn("inbox.rejected", "reason", "aud_mismatch", "caller", string(sender), "aud", string(p.Aud))
			http.Error(w, "envelope audience does not match this lookup", http.StatusUnauthorized)
			return
		}
		if !allowedCaller(d.Identity, sender) {
			d.Logger.Warn("inbox.rejected", "reason", "not_allowed", "caller", string(sender))
			http.Error(w, "sender not accepted", http.StatusForbidden)
			return
		}

		// Registration entry must carry an org.Party — that's the
		// document we're attesting to.
		if _, ok := env.Extract().(*org.Party); !ok {
			d.Logger.Warn("inbox.rejected", "reason", "not_a_party", "caller", string(sender))
			http.Error(w, "registration envelope must contain an org.Party document", http.StatusUnprocessableEntity)
			return
		}

		// Countersign: adds Authority signature with iss=lookup,
		// aud=sender, scope=registered. UUID + digest unchanged.
		err = d.Identity.CounterSign(env, identity.CounterSignOptions{
			Subject: sender,
			Scope:   head.ScopeRegistered,
		})
		if err != nil {
			d.Logger.Error("inbox.countersign_failed", "caller", string(sender), "error", err.Error())
			http.Error(w, "could not countersign envelope", http.StatusInternalServerError)
			return
		}
		// Stamp a discovery link to the public record. Header
		// links are unsigned (mutable post-signature) by design;
		// the link is a discovery hint, not part of the trust
		// claim.
		if d.PublicBaseURL != "" {
			env.Head.Links = append(env.Head.Links, &head.Link{
				Category: "authority",
				Key:      "lookup",
				URL:      d.PublicBaseURL + "/parties/" + env.Head.UUID.String(),
			})
		}

		// Persist before delivery so the record exists even if the
		// downstream POST fails. Re-Get to pick up the existing
		// _rev when the same address has registered before.
		rec, err := upsertRecord(r.Context(), d.Registry, sender, env)
		if err != nil {
			d.Logger.Error("inbox.persist_failed", "caller", string(sender), "error", err.Error())
			http.Error(w, "could not persist record", http.StatusInternalServerError)
			return
		}
		d.Logger.Info("inbox.accepted",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
			"scope", string(head.ScopeRegistered),
		)

		// Fire-and-forget delivery: the client's POST returns 202
		// as soon as we've persisted; the actual /inbox POST to
		// the sender is done asynchronously.
		go deliverAsync(d, sender, env, rec)

		w.WriteHeader(http.StatusAccepted)
	}
}

// upsertRecord reads any existing record for sender (preserving
// the registry's _rev token for optimistic concurrency), then
// writes the new state with the freshly countersigned envelope.
// Re-registration drops scope back to "registered" — if the party
// data has changed, prior KYC no longer applies.
func upsertRecord(ctx context.Context, reg registry.Registrar, sender goblnet.Address, env *gobl.Envelope) (*registry.Record, error) {
	prev, err := reg.Get(ctx, sender)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		r := registry.NewRecord(sender, env.Head.UUID)
		r.Scope = head.ScopeRegistered
		r.Status = registry.StatusCountersigned
		r.CountersignedEnvelope = env
		if _, err := reg.Put(ctx, r); err != nil {
			return nil, err
		}
		return r, nil
	case err != nil:
		return nil, err
	}
	prev.IncomingEnvelopeUUID = env.Head.UUID
	prev.ReceivedAt = time.Now().UTC()
	prev.Scope = head.ScopeRegistered
	prev.Status = registry.StatusCountersigned
	prev.CountersignedEnvelope = env
	prev.DeliveryAttempts = 0
	prev.LastDeliveryError = ""
	prev.LastDeliveryAt = nil
	prev.VerifiedAt = nil
	if _, err := reg.Put(ctx, prev); err != nil {
		return nil, err
	}
	return prev, nil
}

// deliverAsync POSTs the countersigned envelope to the sender's
// own /inbox and records the outcome. The protocol is
// asynchronous; the original POST gets 202 as soon as the record
// is persisted.
func deliverAsync(d Deps, sender goblnet.Address, env *gobl.Envelope, rec *registry.Record) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec.DeliveryAttempts++
	now := time.Now().UTC()
	rec.LastDeliveryAt = &now
	if err := d.Sender.Send(ctx, sender, env); err != nil {
		rec.Status = registry.StatusFailed
		rec.LastDeliveryError = err.Error()
		d.Logger.Warn("inbox.delivery_failed",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
			"attempts", rec.DeliveryAttempts,
			"error", err.Error(),
		)
	} else {
		rec.Status = registry.StatusDelivered
		rec.LastDeliveryError = ""
		d.Logger.Info("inbox.delivered",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
		)
	}
	if _, err := d.Registry.Put(ctx, rec); err != nil {
		d.Logger.Error("inbox.persist_post_delivery_failed",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
			"error", err.Error(),
		)
	}
}
