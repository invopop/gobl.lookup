package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/invopop/couch"
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

	couchConf, err := cfg.CouchConfig()
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}
	client, err := couch.New(couchConf)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(fmt.Errorf("couch client: %w", err))
	}
	if err := client.Ping(ctx); err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(fmt.Errorf("couch ping: %w", err))
	}
	reg, err := repos.NewRegistrations(ctx, client)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}

	var verifiers []goblnet.Address
	for _, v := range cfg.Verifiers {
		addr, err := goblnet.ParseAddress(v)
		if err != nil {
			return nil, nil, gobl.ErrInput.WithReason("invalid verifier address %q", v)
		}
		verifiers = append(verifiers, addr)
	}

	setup := domain.New(domain.Deps{
		Identity:      id,
		Registrations: reg,
		Verifiers:     verifiers,
		// The client and sender authenticate outbound requests as the
		// lookup itself (bearer request tokens, spec §5.5).
		Client: goblnet.NewClient(goblnet.WithIdentity(id.Address(), id.PrivateKey)),
		Sender: delivery.New(id.Address(), id.PrivateKey),
		// domain.New defaults this to https://<domain> when empty.
		PublicBaseURL: strings.TrimRight(cfg.PublicBaseURL, "/"),
		Logger:        slog.Default(),
	})
	cleanup := func() { _ = reg.Close() }
	return setup, cleanup, nil
}
