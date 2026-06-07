package identity_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/note"
	"github.com/invopop/gobl/org"
	"github.com/invopop/gobl/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/identity"
)

func TestInitRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
		PartyName: "Lookup Service",
	})
	require.NoError(t, err)
	assert.Equal(t, net.Address("lookup.example"), id.Address())
	assert.Equal(t, cbc.URI("gobl:lookup.example"), id.URI())
	assert.NotNil(t, id.PrivateKey)
	assert.Len(t, id.PublicKeys, 1)
	assert.Equal(t, "Lookup Service", id.Party.Name)

	// Reload from disk; should recover the same identity.
	id2, err := identity.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, id.PrivateKey.ID(), id2.PrivateKey.ID())
	assert.Equal(t, id.Domain, id2.Domain)
}

func TestInitRejectsExistingDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "marker"), []byte("hi"), 0o644))
	_, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists and is not empty")
}

func TestInitForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "marker"), []byte("hi"), 0o644))
	_, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
		Force:     true,
	})
	require.NoError(t, err)
}

func TestInitRejectsInvalidDomain(t *testing.T) {
	dir := t.TempDir()
	_, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("not a domain"),
		ConfigDir: dir,
	})
	require.Error(t, err)
}

func TestLoadMissingPartyFails(t *testing.T) {
	dir := t.TempDir()
	_, err := identity.Load(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read party.json")
}

func TestLoadRejectsPartyWithoutGoblEndpoint(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, identity.KeysDirName), 0o755))
	party := &org.Party{
		Endpoints: []*org.Endpoint{{URI: cbc.URI("mailto:x@y.example")}},
	}
	data, _ := json.Marshal(party)
	require.NoError(t, os.WriteFile(filepath.Join(dir, identity.PartyFile), data, 0o644))

	_, err := identity.Load(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no gobl: endpoint")
}

func TestLoadRejectsMismatchedKid(t *testing.T) {
	// Scaffold a valid identity, then corrupt the keys/<kid>.json
	// filename so it no longer matches the JWK's kid.
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	kid := id.PrivateKey.ID()
	keysDir := filepath.Join(dir, identity.KeysDirName)
	require.NoError(t, os.Rename(
		filepath.Join(keysDir, kid+".json"),
		filepath.Join(keysDir, "wrong-name.json"),
	))

	_, err = identity.Load(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must equal filename")
}

func TestLoadAllowList(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	assert.Empty(t, id.Allow, "allow defaults to nil when allow.json is absent")

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, identity.AllowFile),
		[]byte(`["alice.example","bob.example"]`),
		0o644,
	))
	id, err = identity.Load(dir)
	require.NoError(t, err)
	assert.Equal(t,
		[]net.Address{"alice.example", "bob.example"},
		id.Allow,
	)
}

func TestLoadAllowListRejectsInvalidAddress(t *testing.T) {
	dir := t.TempDir()
	_, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, identity.AllowFile),
		[]byte(`["not a domain"]`),
		0o644,
	))
	_, err = identity.Load(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address")
}

func TestFindKey(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	require.NotNil(t, id.FindKey(id.PrivateKey.ID()))
	assert.Nil(t, id.FindKey("missing"))
}

func TestJWKSContainsPublishedKeys(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	data, err := id.JWKS()
	require.NoError(t, err)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(data, &set))
	require.Len(t, set.Keys, 1)
}

func TestPartyEnvelopeIsSelfSigned(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	env, err := id.PartyEnvelope(cbc.URI("gobl:alice.example"))
	require.NoError(t, err)
	require.Len(t, env.Signatures, 1)

	p, err := head.SignedPayload(env.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, id.URI(), p.Iss)
	assert.Equal(t, cbc.URI("gobl:alice.example"), p.Aud)
}

func TestCounterSign(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	// Build an envelope that already carries a self-signature (the
	// subject signing their own party).
	subjectKey := id.PrivateKey // reuse — we just want a separate sig
	_ = subjectKey
	msg := &note.Message{Content: "party doc"}
	msg.SetUUID(uuid.V7())
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(id.PrivateKey, cbc.URI("gobl:alice.example"), id.URI()))

	// Authority countersignature.
	require.NoError(t, id.CounterSign(env, identity.CounterSignOptions{
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
	dir := t.TempDir()
	id, err := identity.Init(identity.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	err = id.CounterSign(nil, identity.CounterSignOptions{Subject: "alice.example"})
	require.Error(t, err)
}
