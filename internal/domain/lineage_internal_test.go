package domain

import (
	"testing"
	"time"

	"github.com/invopop/gobl/dsig"
	goblnet "github.com/invopop/gobl/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

func TestNextLineage(t *testing.T) {
	now := time.Now()
	a, b, c := dsig.NewES256Key(), dsig.NewES256Key(), dsig.NewES256Key()
	// conf is a confirming signature by k, naming next (if any) as
	// its successor.
	conf := func(k, next *dsig.PrivateKey) *goblnet.ConfirmingSignature {
		c := &goblnet.ConfirmingSignature{Key: k.Public(), IssuedAt: now}
		if next != nil {
			c.Successor = next.JKT()
		}
		return c
	}
	// change is a key change request from k to next.
	change := func(k, next *dsig.PrivateKey) []*goblnet.ConfirmingSignature {
		return []*goblnet.ConfirmingSignature{conf(next, nil), conf(k, next)}
	}
	lineage := func(ks ...*dsig.PrivateKey) []*models.LineageKey {
		out := make([]*models.LineageKey, len(ks))
		for i, k := range ks {
			out[i] = &models.LineageKey{JKT: k.JKT(), KID: k.ID()}
		}
		return out
	}
	jkts := func(l []*models.LineageKey) []string {
		out := make([]string, len(l))
		for i, k := range l {
			out[i] = k.JKT
		}
		return out
	}

	t.Run("renews with the current key", func(t *testing.T) {
		got, err := nextLineage(lineage(a), []*goblnet.ConfirmingSignature{conf(a, nil)}, nil, now)
		require.NoError(t, err)
		assert.Equal(t, []string{a.JKT()}, jkts(got))
	})

	t.Run("starts afresh with one key that is not current", func(t *testing.T) {
		got, err := nextLineage(lineage(a), []*goblnet.ConfirmingSignature{conf(b, nil)}, nil, now)
		require.NoError(t, err)
		assert.Equal(t, []string{b.JKT()}, jkts(got))
	})

	t.Run("changes to the key the current key names", func(t *testing.T) {
		got, err := nextLineage(lineage(a), change(a, b), nil, now)
		require.NoError(t, err)
		assert.Equal(t, []string{a.JKT(), b.JKT()}, jkts(got))
	})

	t.Run("rejects a key change the current key does not name", func(t *testing.T) {
		both := []*goblnet.ConfirmingSignature{conf(a, nil), conf(b, nil)}
		_, err := nextLineage(lineage(a), both, nil, now)
		assert.ErrorIs(t, err, errLineage)
		// Naming another key does not count either.
		_, err = nextLineage(lineage(a), []*goblnet.ConfirmingSignature{conf(a, c), conf(b, nil)}, nil, now)
		assert.ErrorIs(t, err, errLineage)
		// Nor does the new key naming the current one.
		_, err = nextLineage(lineage(a), change(b, a), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("rejects a key bound before becoming current again", func(t *testing.T) {
		_, err := nextLineage(lineage(a, b), change(b, a), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("rejects two keys neither of which is current", func(t *testing.T) {
		_, err := nextLineage(lineage(a), change(b, c), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("orders a first registration by the verified key", func(t *testing.T) {
		got, err := nextLineage(nil, change(b, a), []string{b.JKT()}, now)
		require.NoError(t, err)
		assert.Equal(t, []string{b.JKT(), a.JKT()}, jkts(got))
	})

	t.Run("rejects a first registration whose verified key names no other", func(t *testing.T) {
		_, err := nextLineage(nil, []*goblnet.ConfirmingSignature{conf(a, nil), conf(b, nil)}, []string{b.JKT()}, now)
		assert.ErrorIs(t, err, errLineage)
		_, err = nextLineage(nil, change(a, b), []string{b.JKT()}, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("rejects a first registration with both or neither key verified", func(t *testing.T) {
		_, err := nextLineage(nil, change(a, b), []string{a.JKT(), b.JKT()}, now)
		assert.ErrorIs(t, err, errLineage)
		_, err = nextLineage(nil, change(a, b), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("rejects more than two keys", func(t *testing.T) {
		_, err := nextLineage(lineage(a), append(change(a, b), conf(c, nil)), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})
}

func TestFreshConfirmations(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) *goblnet.ConfirmingSignature {
		return &goblnet.ConfirmingSignature{Key: dsig.NewES256Key().Public(), IssuedAt: now.Add(d)}
	}
	fresh, edge, stale := at(-time.Minute), at(-goblnet.MaxRequestAge-requestClockSkew), at(-time.Hour)
	got := freshConfirmations([]*goblnet.ConfirmingSignature{fresh, stale, edge}, now)
	assert.Equal(t, []*goblnet.ConfirmingSignature{fresh, edge}, got)
	assert.Empty(t, freshConfirmations([]*goblnet.ConfirmingSignature{stale}, now))
}

func TestInLineage(t *testing.T) {
	k := dsig.NewES256Key()
	l := []*models.LineageKey{{JKT: k.JKT()}}
	assert.True(t, inLineage(l, k.JKT()))
	assert.False(t, inLineage(l, ""))
	assert.False(t, inLineage(l, "other"))
}
