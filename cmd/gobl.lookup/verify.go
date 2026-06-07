package main

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb"
	"github.com/spf13/cobra"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/delivery"
	"github.com/invopop/gobl.lookup/internal/identity"
	"github.com/invopop/gobl.lookup/internal/registry"
)

type verifyOpts struct {
	configDir string
	couchURL  string
	couchDB   string
}

func verifyCmd() *cobra.Command {
	opts := &verifyOpts{couchDB: "gobl-lookup"}
	cmd := &cobra.Command{
		Use:   "verify <address>",
		Short: "Bump a registration's scope to `verified` after out-of-band KYC",
		Long: `Load the existing registration for <address>, countersign the
stored party envelope with head.ScopeVerified, deliver the new
envelope to the subject's /inbox, and update the registry record
(scope=verified, verified_at=now).

The original Authority countersignature on the previous record
remains in the audit history (CouchDB revisions).  This command
issues a fresh signature; the subject can publish either or both.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.configDir == "" {
				return gobl.ErrInput.WithReason("--config-dir is required")
			}
			if opts.couchURL == "" {
				return gobl.ErrInput.WithReason("--couchdb is required")
			}
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			ctx := cmd.Context()

			id, err := identity.Load(opts.configDir)
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			client, err := kivik.New("couch", opts.couchURL)
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			store, err := registry.NewCouchStore(ctx, client, opts.couchDB)
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			defer store.Close() //nolint:errcheck

			rec, err := store.Get(ctx, addr)
			if errors.Is(err, registry.ErrNotFound) {
				return gobl.ErrInput.WithReason("no registration for %s", addr)
			}
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			if rec.CountersignedEnvelope == nil {
				return gobl.ErrInput.WithReason("registration for %s has no countersigned envelope", addr)
			}
			env := rec.CountersignedEnvelope

			// Stamp a fresh Authority signature with the verified
			// scope onto the existing envelope.
			if err := id.CounterSign(env, identity.CounterSignOptions{
				Subject: addr,
				Scope:   head.ScopeVerified,
			}); err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			rec.Scope = head.ScopeVerified
			now := time.Now().UTC()
			rec.VerifiedAt = &now
			rec.Status = registry.StatusCountersigned

			sender := delivery.NewSender()
			if err := sender.Send(ctx, addr, env); err != nil {
				rec.Status = registry.StatusFailed
				rec.LastDeliveryError = err.Error()
				rec.LastDeliveryAt = &now
				_, _ = store.Put(ctx, rec)
				return gobl.ErrInternal.WithCause(fmt.Errorf("deliver verified envelope: %w", err))
			}
			rec.Status = registry.StatusDelivered
			rec.LastDeliveryError = ""
			rec.LastDeliveryAt = &now
			rec.DeliveryAttempts++
			if _, err := store.Put(ctx, rec); err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			slog.Info("verified registration",
				"address", string(addr),
				"envelope", env.Head.UUID.String(),
				"scope", string(head.ScopeVerified),
			)
			_, _ = fmt.Fprintf(stdOut(cmd), "verified %s (envelope %s)\n", addr, env.Head.UUID)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.configDir, "config-dir", "", "directory holding the lookup identity")
	cmd.Flags().StringVar(&opts.couchURL, "couchdb", "", "CouchDB URL")
	cmd.Flags().StringVar(&opts.couchDB, "couchdb-database", opts.couchDB, "CouchDB database name")
	return cmd
}
