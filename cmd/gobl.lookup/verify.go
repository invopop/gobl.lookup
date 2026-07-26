package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/config"
	"github.com/invopop/gobl.lookup/internal/domain"
)

func verifyCmd() *cobra.Command {
	cfg := config.FromEnv()
	cmd := &cobra.Command{
		Use:   "verify <address>",
		Short: "Re-derive a registration's verified status from its countersignatures",
		Long: `Load the existing registration for <address>, find the most recent
countersignature from an accepted verification provider (the
configured --verifiers list) on the stored party envelope,
countersign with a verifier claim naming it, deliver the new
envelope to the subject's /inbox, and update the registry record
(verifier=<addr>, verified_at=now).

The same derivation runs automatically when a registration arrives
carrying a provider countersignature; this command exists for
recovery — e.g. a provider added to the accepted list after its
countersignature was received.

The original Authority countersignature on the previous record
remains in the audit history (CouchDB revisions).  This command
issues a fresh signature; the subject can publish either or both.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ConfigDir == "" {
				return gobl.ErrInput.WithReason("identity directory required: set --config-dir or CONFIG_DIR")
			}
			if cfg.CouchDBURL() == "" {
				return gobl.ErrInput.WithReason("CouchDB connection required: set --couchdb / COUCHDB_URL, or COUCHDB_HOST (+ COUCHDB_USERNAME / COUCHDB_PASSWORD)")
			}
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			ctx := cmd.Context()

			setup, cleanup, err := buildDomain(ctx, cfg)
			if err != nil {
				return err
			}
			defer cleanup()

			rec, err := setup.Registrations().Verify(ctx, addr)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrValidation) {
					return gobl.ErrInput.WithCause(err)
				}
				return gobl.ErrInternal.WithCause(err)
			}
			slog.Info("verified registration",
				"address", string(addr),
				"envelope", rec.IncomingEnvelopeUUID.String(),
				"verifier", string(rec.Verifier),
			)
			_, _ = fmt.Fprintf(stdOut(cmd), "verified %s by %s (envelope %s)\n", addr, rec.Verifier, rec.IncomingEnvelopeUUID)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "directory holding the lookup identity (env CONFIG_DIR)")
	cmd.Flags().StringVar(&cfg.CouchURL, "couchdb", cfg.CouchURL, "full CouchDB URL (env COUCHDB_URL; overrides the COUCHDB_* parts)")
	cmd.Flags().StringVar(&cfg.CouchDatabase, "couchdb-database", cfg.CouchDatabase, "CouchDB database name (env COUCHDB_DATABASE)")
	cmd.Flags().StringSliceVar(&cfg.Verifiers, "verifiers", cfg.Verifiers, "accepted verification-provider addresses (env VERIFIERS, comma-separated)")
	return cmd
}
