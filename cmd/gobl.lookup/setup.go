package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb" // register the couchdb driver

	"github.com/invopop/gobl"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/config"
	"github.com/invopop/gobl.lookup/internal/domain"
	"github.com/invopop/gobl.lookup/internal/domain/delivery"
	"github.com/invopop/gobl.lookup/internal/domain/repos"
)

// buildDomain wires the domain setup from configuration: it loads the
// identity, connects to CouchDB, and constructs the registration
// store, GOBL Net client, and outbound sender. The returned cleanup
// closes the CouchDB connection and must be called by the caller.
func buildDomain(ctx context.Context, cfg config.Config) (*domain.Setup, func(), error) {
	id, err := repos.LoadIdentity(cfg.ConfigDir)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}

	client, err := kivik.New("couch", cfg.CouchDBURL())
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(fmt.Errorf("couchdb client: %w", err))
	}
	reg, err := repos.NewRegistrations(ctx, client, cfg.CouchDatabase)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}

	base := strings.TrimRight(cfg.PublicBaseURL, "/")
	if base == "" {
		base = "https://" + string(id.Address())
	}

	setup := domain.New(domain.Deps{
		Identity:      id,
		Registrations: reg,
		Client:        goblnet.NewClient(),
		Sender:        delivery.New(),
		PublicBaseURL: base,
		Logger:        slog.Default(),
	})
	cleanup := func() { _ = reg.Close() }
	return setup, cleanup, nil
}
