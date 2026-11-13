package domain

import (
	"errors"
	"time"

	"github.com/invopop/gobl/dsig"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// errLineage is returned when a registration request's keys cannot
// extend or start a lineage.
var errLineage = errors.New("registration must be signed with the current key, a new key, or both")

// nextLineage applies the keys confirming a registration request to
// the current lineage (spec §7.3) and returns the resulting one, whose
// last key is bound. verified holds the cnf thumbprints of accepted
// verification countersignatures on the request, which order the keys
// of a first registration signed with two.
func nextLineage(lineage []*models.LineageKey, keys []*dsig.PublicKey, verified []string, now time.Time) ([]*models.LineageKey, error) {
	entry := func(k *dsig.PublicKey) *models.LineageKey {
		return &models.LineageKey{JKT: k.JKT(), KID: k.ID(), AddedAt: now}
	}
	var current string
	if len(lineage) > 0 {
		current = lineage[len(lineage)-1].JKT
	}
	switch len(keys) {
	case 1:
		k := keys[0]
		if k.JKT() == current {
			return lineage, nil // renewal
		}
		// A first registration, or a key that is not the current one:
		// a lost key or a new holder of the address starts afresh.
		return []*models.LineageKey{entry(k)}, nil
	case 2:
		a, b := keys[0], keys[1]
		if current != "" {
			switch current {
			case a.JKT():
				return append(lineage, entry(b)), nil
			case b.JKT():
				return append(lineage, entry(a)), nil
			}
			return nil, errLineage
		}
		switch {
		case contains(verified, a.JKT()) && !contains(verified, b.JKT()):
			return []*models.LineageKey{entry(a), entry(b)}, nil
		case contains(verified, b.JKT()) && !contains(verified, a.JKT()):
			return []*models.LineageKey{entry(b), entry(a)}, nil
		}
		return nil, errLineage
	}
	return nil, errLineage
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
