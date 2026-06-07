package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"
)

// MemoryStore is a thread-safe in-process Registrar useful for
// tests and local dev. It preserves _rev-style optimistic
// concurrency so callers exercising the conflict path behave the
// same as against CouchDB.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]*Record
}

// NewMemoryStore returns an empty in-memory registry.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]*Record)}
}

// Put implements Registrar.
func (m *MemoryStore) Put(_ context.Context, r *Record) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, exists := m.records[r.ID]
	if exists {
		if r.Rev != prev.Rev {
			return "", ErrConflict
		}
	} else if r.Rev != "" {
		return "", ErrConflict
	}
	r.Rev = newRev()
	clone := *r
	m.records[r.ID] = &clone
	return r.Rev, nil
}

// Get implements Registrar.
func (m *MemoryStore) Get(_ context.Context, address net.Address) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[DocID(address)]
	if !ok {
		return nil, ErrNotFound
	}
	clone := *r
	return &clone, nil
}

// GetByUUID implements Registrar.
func (m *MemoryStore) GetByUUID(_ context.Context, id uuid.UUID) (*Record, error) {
	target := id.String()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.records {
		if r.IncomingEnvelopeUUID.String() == target {
			clone := *r
			return &clone, nil
		}
	}
	return nil, ErrNotFound
}

// newRev generates an opaque revision string. Format mirrors
// CouchDB's "1-<hex>" shape just for parity; the leading integer
// is purely informational.
func newRev() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal; surface so tests notice.
		panic("registry: crypto/rand unavailable: " + err.Error())
	}
	return "1-" + hex.EncodeToString(b[:])
}

