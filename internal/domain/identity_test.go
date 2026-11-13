package domain_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/invopop/gobl"
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

func TestPartyEnvelopeIsSignedForTheRequester(t *testing.T) {
	id := newTestIdentity(t)

	data, err := id.PartyEnvelope("alice.example")
	require.NoError(t, err)
	env := new(gobl.Envelope)
	require.NoError(t, json.Unmarshal(data, env))
	require.Len(t, env.Signatures, 1)
	assert.Equal(t, id.URI(), env.Head.From)
	assert.Equal(t, "gobl:alice.example", env.Head.To.String())

	p, err := head.SignedPayload(env.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, id.Address().String(), p.Iss)
	assert.Equal(t, "alice.example", p.Aud)

	// Each requester gets its own signature over the same document.
	other, err := id.PartyEnvelope("bob.example")
	require.NoError(t, err)
	envB := new(gobl.Envelope)
	require.NoError(t, json.Unmarshal(other, envB))
	assert.Equal(t, env.Head.UUID, envB.Head.UUID)
	pb, err := head.SignedPayload(envB.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, "bob.example", pb.Aud)
}

func TestCounterSign(t *testing.T) {
	id := newTestIdentity(t)

	// Build an envelope that already carries a self-signature.
	msg := &note.Message{Content: "party doc"}
	msg.SetUUID(uuid.V7())
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(id.Model().PrivateKey,
		head.WithIssuer("alice.example"),
		head.WithAudience(id.Address().String())))

	// Authority countersignature.
	require.NoError(t, id.CounterSign(env, domain.CounterSignOptions{
		Subject:  net.Address("alice.example"),
		Key:      "alice-key",
		Verifier: net.Address("kyc.example"),
	}))
	require.Len(t, env.Signatures, 2)
	assert.Equal(t, id.URI(), env.Head.From)
	assert.Equal(t, "gobl:alice.example", env.Head.To.String())

	p, err := head.SignedPayload(env.Signatures[1])
	require.NoError(t, err)
	assert.Equal(t, id.Address().String(), p.Iss)
	assert.Equal(t, "alice.example", p.Aud)
	assert.Equal(t, "kyc.example", p.Verifier)
	require.NotNil(t, p.Confirmation)
	assert.Equal(t, "alice-key", p.Confirmation.JKT)
	assert.NotZero(t, p.ExpiresAt)
}

func TestCounterSignRequiresAKey(t *testing.T) {
	id := newTestIdentity(t)
	env, err := gobl.Envelop(&note.Message{Content: "party doc"})
	require.NoError(t, err)
	require.Error(t, id.CounterSign(env, domain.CounterSignOptions{Subject: "alice.example"}))
}

func TestCounterSignNilEnvelope(t *testing.T) {
	id := newTestIdentity(t)
	err := id.CounterSign(nil, domain.CounterSignOptions{Subject: "alice.example"})
	require.Error(t, err)
}
