// Package identity loads and persists the lookup service's GOBL Net
// identity from disk. The on-disk layout matches gobl.dev's node
// convention so operators get a familiar mental model:
//
//	~/.config/gobl.lookup/
//	├── private.jwk        active signing key (mode 0600)
//	├── party.json         lookup's own org.Party (served at /who)
//	├── keys/<kid>.json    each published JWK (served at /keys/<kid>)
//	└── allow.json         optional caller allow-list (usually absent)
package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cal"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
)

// File names within the identity directory.
const (
	PrivateKeyFile = "private.jwk"
	PartyFile      = "party.json"
	KeysDirName    = "keys"
	AllowFile      = "allow.json"
)

// Identity holds the lookup service's signing identity, its
// advertised party, and every public key it has ever published
// (active + retired).
type Identity struct {
	// Domain is the lookup's GOBL Net address (e.g. "lookup.gobl.org").
	Domain net.Address
	// PrivateKey is the active signing key. Its kid MUST appear in
	// PublicKeys.
	PrivateKey *dsig.PrivateKey
	// PublicKeys are every key the lookup has published, served at
	// /.well-known/gobl/keys/<kid> and aggregated at /.well-known/jwks.json.
	PublicKeys []*dsig.PublicKey
	// Party is the lookup's own org.Party served at /.well-known/gobl/who.
	// Stored unsigned on disk; signed per-request.
	Party *org.Party
	// Allow gates inbox / who requests by caller address. Empty means
	// "accept any verified caller".
	Allow []net.Address

	configDir string
}

// Address returns the lookup's address.
func (i *Identity) Address() net.Address { return i.Domain }

// URI returns the gobl: URI form of the lookup's address.
func (i *Identity) URI() cbc.URI { return i.Domain.URI() }

// PartyEnvelope returns the lookup's party wrapped in a freshly
// signed envelope, suitable for serving at /.well-known/gobl/who.
// `aud` is the caller's address (the /who exchange is mutual; the
// response is bound to the caller).
func (i *Identity) PartyEnvelope(aud cbc.URI) (*gobl.Envelope, error) {
	env, err := gobl.Envelop(i.Party)
	if err != nil {
		return nil, fmt.Errorf("identity: envelop party: %w", err)
	}
	if err := env.Sign(i.PrivateKey, i.URI(), aud); err != nil {
		return nil, fmt.Errorf("identity: sign party: %w", err)
	}
	return env, nil
}

// Load reads an identity from configDir. Returns an error if the
// directory is missing or any required file is absent / malformed.
func Load(configDir string) (*Identity, error) {
	id := &Identity{configDir: configDir}

	// Domain is encoded in the directory name (the operator scaffolds
	// `~/.config/gobl.lookup/<domain>/`) OR — single-tenant default —
	// the directory is the identity itself with the domain stored on
	// the party's `gobl:` endpoint. Single-tenant is the common case;
	// derive Domain from the party's first `gobl:` endpoint.
	pdata, err := os.ReadFile(filepath.Join(configDir, PartyFile))
	if err != nil {
		return nil, fmt.Errorf("identity: read party.json: %w", err)
	}
	id.Party = new(org.Party)
	if err := json.Unmarshal(pdata, id.Party); err != nil {
		return nil, fmt.Errorf("identity: parse party.json: %w", err)
	}
	ep := id.Party.Endpoint(net.Scheme)
	if ep == nil {
		return nil, errors.New("identity: party.json has no gobl: endpoint — set one before serving")
	}
	addr, err := net.ParseAddress(ep.URI.Opaque())
	if err != nil {
		return nil, fmt.Errorf("identity: party gobl endpoint %q is not a valid address: %w", ep.URI, err)
	}
	id.Domain = addr

	pkdata, err := os.ReadFile(filepath.Join(configDir, PrivateKeyFile))
	if err != nil {
		return nil, fmt.Errorf("identity: read private.jwk: %w", err)
	}
	id.PrivateKey = new(dsig.PrivateKey)
	if err := json.Unmarshal(pkdata, id.PrivateKey); err != nil {
		return nil, fmt.Errorf("identity: parse private.jwk: %w", err)
	}
	if err := id.PrivateKey.Validate(); err != nil {
		return nil, fmt.Errorf("identity: private.jwk invalid: %w", err)
	}

	keys, err := loadKeys(filepath.Join(configDir, KeysDirName))
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("identity: no published keys found under keys/")
	}
	// The active private key's kid MUST appear in the published set.
	found := false
	for _, k := range keys {
		if k.ID() == id.PrivateKey.ID() {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("identity: active private.jwk kid %q is not in keys/", id.PrivateKey.ID())
	}
	id.PublicKeys = keys

	id.Allow, err = loadAllow(filepath.Join(configDir, AllowFile))
	if err != nil {
		return nil, err
	}

	return id, nil
}

// FindKey returns the public key whose kid matches, or nil.
func (i *Identity) FindKey(kid string) *dsig.PublicKey {
	for _, k := range i.PublicKeys {
		if k.ID() == kid {
			return k
		}
	}
	return nil
}

// JWKS marshals the published keys into a single RFC 7517 JWK Set
// document, newest first (sorted by ValidFrom descending; keys with
// no ValidFrom sort last). Used by the /.well-known/jwks.json
// handler.
func (i *Identity) JWKS() ([]byte, error) {
	type set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	out := set{Keys: make([]json.RawMessage, 0, len(i.PublicKeys))}
	keys := append([]*dsig.PublicKey(nil), i.PublicKeys...)
	sort.SliceStable(keys, func(a, b int) bool {
		ka, kb := keys[a], keys[b]
		switch {
		case ka.ValidFrom != nil && kb.ValidFrom != nil:
			if !ka.ValidFrom.Equal(kb.ValidFrom.Time) {
				return ka.ValidFrom.After(kb.ValidFrom.Time)
			}
		case ka.ValidFrom != nil && kb.ValidFrom == nil:
			return true
		case ka.ValidFrom == nil && kb.ValidFrom != nil:
			return false
		}
		return ka.ID() > kb.ID()
	})
	for _, k := range keys {
		b, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("identity: marshal jwks entry: %w", err)
		}
		out.Keys = append(out.Keys, b)
	}
	return json.Marshal(out)
}

func loadKeys(dir string) ([]*dsig.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("identity: read keys dir: %w", err)
	}
	out := make([]*dsig.PublicKey, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		expectedKid := strings.TrimSuffix(e.Name(), ".json")
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("identity: read keys/%s: %w", e.Name(), err)
		}
		pk := new(dsig.PublicKey)
		if err := json.Unmarshal(data, pk); err != nil {
			return nil, fmt.Errorf("identity: parse keys/%s: %w", e.Name(), err)
		}
		if pk.ID() != expectedKid {
			return nil, fmt.Errorf("identity: keys/%s has kid %q (must equal filename)", e.Name(), pk.ID())
		}
		out = append(out, pk)
	}
	return out, nil
}

func loadAllow(path string) ([]net.Address, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read allow.json: %w", err)
	}
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("identity: parse allow.json: %w", err)
	}
	out := make([]net.Address, 0, len(raw))
	for _, s := range raw {
		a, err := net.ParseAddress(s)
		if err != nil {
			return nil, fmt.Errorf("identity: allow.json contains invalid address %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// ScaffoldOptions configure Init.
type ScaffoldOptions struct {
	Domain    net.Address
	ConfigDir string
	Force     bool   // overwrite existing files
	PartyName string // optional name to seed into party.json
}

// Init scaffolds a fresh identity directory: generates an ES256
// keypair, writes private.jwk (0600) and keys/<kid>.json with
// valid_from=now, and writes a party.json template carrying the
// gobl:<domain> endpoint.
func Init(opts ScaffoldOptions) (*Identity, error) {
	if opts.Domain == "" {
		return nil, errors.New("identity: Init requires a Domain")
	}
	if err := opts.Domain.Validate(); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if opts.ConfigDir == "" {
		return nil, errors.New("identity: Init requires a ConfigDir")
	}

	if !opts.Force {
		if entries, _ := os.ReadDir(opts.ConfigDir); len(entries) > 0 {
			return nil, fmt.Errorf("identity: %s already exists and is not empty (use Force to overwrite)", opts.ConfigDir)
		}
	}
	if err := os.MkdirAll(filepath.Join(opts.ConfigDir, KeysDirName), 0o700); err != nil {
		return nil, fmt.Errorf("identity: create dirs: %w", err)
	}

	priv := dsig.NewES256Key()
	pub := priv.Public()
	from := cal.TimestampNow()
	pub.ValidFrom = &from

	if err := writeJSON(filepath.Join(opts.ConfigDir, PrivateKeyFile), priv, 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(opts.ConfigDir, KeysDirName, pub.ID()+".json"), pub, 0o644); err != nil {
		return nil, err
	}

	party := &org.Party{
		Endpoints: []*org.Endpoint{{URI: opts.Domain.URI()}},
	}
	if opts.PartyName != "" {
		party.Name = opts.PartyName
	}
	if err := writeJSON(filepath.Join(opts.ConfigDir, PartyFile), party, 0o644); err != nil {
		return nil, err
	}

	return Load(opts.ConfigDir)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

// CounterSignOptions configure a CounterSign call.
type CounterSignOptions struct {
	// Subject is the address of the party whose envelope is being
	// countersigned; copied into the signed `aud` field so the
	// resulting signature is bound to that specific subject.
	Subject net.Address
	// Scope is the Authority's confidence assertion (typically
	// head.ScopeRegistered for an initial registration,
	// head.ScopeVerified after KYC). Empty leaves Scope unset.
	Scope cbc.Key
}

// CounterSign adds a fresh Authority countersignature to env. The
// envelope's UUID and Digest are unchanged — only the Signatures
// slice grows. Returns the new signature for caller inspection /
// logging.
func (i *Identity) CounterSign(env *gobl.Envelope, opts CounterSignOptions) error {
	if env == nil || env.Head == nil {
		return errors.New("identity: cannot countersign a nil envelope")
	}
	signOpts := []head.SignOption{}
	if opts.Scope != "" {
		signOpts = append(signOpts, head.WithScope(opts.Scope))
	}
	return env.Sign(i.PrivateKey, i.URI(), opts.Subject.URI(), signOpts...)
}
