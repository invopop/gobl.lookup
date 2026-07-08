package domain_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/note"
	"github.com/invopop/gobl/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/domain"
	"github.com/invopop/gobl.lookup/internal/domain/repos"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newIdentity scaffolds a lookup identity in a tempdir and returns the
// wrapping domain service.
func newTestIdentity(t *testing.T) *domain.Identity {
	t.Helper()
	dir := t.TempDir()
	id, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	setup := domain.New(domain.Deps{Identity: id, Logger: discardLogger()})
	return setup.Identity()
}

func TestPartyEnvelopeIsSelfSigned(t *testing.T) {
	id := newTestIdentity(t)

	env, err := id.PartyEnvelope(cbc.URI("gobl:alice.example"))
	require.NoError(t, err)
	require.Len(t, env.Signatures, 1)

	p, err := head.SignedPayload(env.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, id.URI(), p.Iss)
	assert.Equal(t, cbc.URI("gobl:alice.example"), p.Aud)
}

func TestCounterSign(t *testing.T) {
	id := newTestIdentity(t)

	// Build an envelope that already carries a self-signature.
	msg := &note.Message{Content: "party doc"}
	msg.SetUUID(uuid.V7())
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(id.Model().PrivateKey, cbc.URI("gobl:alice.example"), id.URI()))

	// Authority countersignature.
	require.NoError(t, id.CounterSign(env, domain.CounterSignOptions{
		Subject: net.Address("alice.example"),
		Scope:   head.ScopeRegistered,
	}))
	require.Len(t, env.Signatures, 2)

	p, err := head.SignedPayload(env.Signatures[1])
	require.NoError(t, err)
	assert.Equal(t, id.URI(), p.Iss)
	assert.Equal(t, cbc.URI("gobl:alice.example"), p.Aud)
	assert.Equal(t, head.ScopeRegistered, p.Scope)
}

func TestCounterSignNilEnvelope(t *testing.T) {
	id := newTestIdentity(t)
	err := id.CounterSign(nil, domain.CounterSignOptions{Subject: "alice.example"})
	require.Error(t, err)
}
