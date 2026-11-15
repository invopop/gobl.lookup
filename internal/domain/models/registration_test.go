package models_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

func TestRegistrationCurrentKey(t *testing.T) {
	r := new(models.Registration)
	assert.Nil(t, r.CurrentKey())
	r.Lineage = []*models.LineageKey{{JKT: "a"}, {JKT: "b"}}
	assert.Equal(t, "b", r.CurrentKey().JKT)
}
