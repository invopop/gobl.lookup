package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.lookup/internal/config"
	"github.com/invopop/gobl.lookup/internal/interfaces/web"
)

func serveCmd() *cobra.Command {
	cfg := config.FromEnv()
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the lookup HTTP server",
		Long: `Run the GOBL Net Authority server.  Loads the identity from
--config-dir, connects to CouchDB, and serves the standard
well-known endpoints plus /parties/<key> for public record
lookups.

Configuration is read from the environment (CONFIG_DIR, COUCHDB_*,
PUBLIC_BASE_URL, HTTP_PORT/PORT); the flags below override it.

NOTE: This v1 binary terminates HTTP only (no built-in TLS).
Deploy behind a reverse proxy that handles TLS termination.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.ConfigDir == "" {
				return gobl.ErrInput.WithReason("identity directory required: set --config-dir or CONFIG_DIR")
			}
			if cfg.CouchDBURL() == "" {
				return gobl.ErrInput.WithReason("CouchDB connection required: set --couchdb / COUCHDB_URL, or COUCHDB_HOST (+ COUCHDB_USERNAME / COUCHDB_PASSWORD)")
			}
			ctx := cmd.Context()

			setup, cleanup, err := buildDomain(ctx, cfg)
			if err != nil {
				return err
			}
			defer cleanup()

			mux := web.NewMux(setup, slog.Default())

			addr := fmt.Sprintf(":%d", cfg.HTTPPort)
			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				slog.Info("GOBL Lookup listening",
					"addr", addr,
					"domain", string(setup.Identity().Address()),
					"public_base_url", setup.PublicBaseURL(),
					"couchdb", cfg.CouchDBRedacted(),
				)
				errCh <- srv.ListenAndServe()
			}()

			select {
			case err := <-errCh:
				if err != nil && err != http.ErrServerClosed {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
				defer cancel()
				slog.Info("shutting down")
				if err := srv.Shutdown(shutdownCtx); err != nil {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "directory holding the lookup identity (env CONFIG_DIR)")
	cmd.Flags().StringVar(&cfg.CouchURL, "couchdb", cfg.CouchURL, "full CouchDB URL, e.g. http://admin:pass@localhost:5984 (env COUCHDB_URL; overrides the COUCHDB_* parts)")
	cmd.Flags().StringVar(&cfg.CouchDatabase, "couchdb-database", cfg.CouchDatabase, "CouchDB database name (env COUCHDB_DATABASE)")
	cmd.Flags().IntVar(&cfg.HTTPPort, "http-port", cfg.HTTPPort, "HTTP listen port (env HTTP_PORT or PORT)")
	cmd.Flags().StringVar(&cfg.PublicBaseURL, "public-base-url", cfg.PublicBaseURL, "canonical https URL used to build /parties/<uuid> links, defaults to https://<domain> (env PUBLIC_BASE_URL)")
	cmd.Flags().StringSliceVar(&cfg.Verifiers, "verifiers", cfg.Verifiers, "accepted verification-provider addresses (env VERIFIERS, comma-separated)")
	return cmd
}
