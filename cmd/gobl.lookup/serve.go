package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb"
	"github.com/spf13/cobra"

	"github.com/invopop/gobl"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/delivery"
	"github.com/invopop/gobl.lookup/internal/identity"
	"github.com/invopop/gobl.lookup/internal/registry"
	"github.com/invopop/gobl.lookup/internal/server"
)

type serveOpts struct {
	configDir       string
	couchURL        string
	couchDB         string
	httpPort        int
	publicBaseURL   string
	shutdownTimeout time.Duration
}

func serveCmd() *cobra.Command {
	opts := &serveOpts{
		couchDB:         "gobl-lookup",
		httpPort:        80,
		shutdownTimeout: 10 * time.Second,
	}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the lookup HTTP server",
		Long: `Run the GOBL Net Authority server.  Loads the identity from
--config-dir, connects to CouchDB, and serves the standard
well-known endpoints plus /parties/<key> for public record
lookups.

NOTE: This v1 binary terminates HTTP only (no built-in TLS).
Deploy behind a reverse proxy that handles TLS termination.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.configDir == "" {
				return gobl.ErrInput.WithReason("--config-dir is required")
			}
			if opts.couchURL == "" {
				return gobl.ErrInput.WithReason("--couchdb is required")
			}
			ctx := cmd.Context()

			id, err := identity.Load(opts.configDir)
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}

			client, err := kivik.New("couch", opts.couchURL)
			if err != nil {
				return gobl.ErrInternal.WithCause(fmt.Errorf("couchdb client: %w", err))
			}
			reg, err := registry.NewCouchStore(ctx, client, opts.couchDB)
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			defer reg.Close() //nolint:errcheck

			netClient := goblnet.NewClient()
			sender := delivery.NewSender()

			base := strings.TrimRight(opts.publicBaseURL, "/")
			if base == "" {
				base = "https://" + string(id.Address())
			}
			mux := server.NewMux(server.Deps{
				Identity:      id,
				Registry:      reg,
				Client:        netClient,
				Sender:        sender,
				Logger:        slog.Default(),
				PublicBaseURL: base,
			})

			addr := fmt.Sprintf(":%d", opts.httpPort)
			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				slog.Info("GOBL Lookup listening",
					"addr", addr,
					"domain", string(id.Address()),
					"public_base_url", base,
					"couchdb", opts.couchURL,
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
				shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.shutdownTimeout)
				defer cancel()
				slog.Info("shutting down")
				if err := srv.Shutdown(shutdownCtx); err != nil {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&opts.configDir, "config-dir", "", "directory holding the lookup identity (private.jwk + party.json + keys/)")
	cmd.Flags().StringVar(&opts.couchURL, "couchdb", "", "CouchDB URL, e.g. http://admin:pass@localhost:5984/")
	cmd.Flags().StringVar(&opts.couchDB, "couchdb-database", opts.couchDB, "CouchDB database name (default \"gobl-lookup\")")
	cmd.Flags().IntVar(&opts.httpPort, "http-port", opts.httpPort, "HTTP listen port")
	cmd.Flags().StringVar(&opts.publicBaseURL, "public-base-url", "", "canonical https URL used to build /parties/<uuid> links (defaults to https://<domain>)")
	return cmd
}
