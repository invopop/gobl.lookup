package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/invopop/gobl.lookup/internal/config"
)

func TestFromEnvReadsCouchParts(t *testing.T) {
	t.Setenv("CONFIG_DIR", "/etc/lookup")
	t.Setenv("COUCHDB_HOST", "couchdb-svc.default")
	t.Setenv("COUCHDB_USERNAME", "lookup")
	t.Setenv("COUCHDB_PASSWORD", "s3cr3t/p@ss")
	t.Setenv("COUCHDB_DATABASE", "gobl-lookup")
	t.Setenv("PUBLIC_BASE_URL", "https://lookup.example")

	cfg := config.FromEnv()
	assert.Equal(t, "/etc/lookup", cfg.ConfigDir)
	assert.Equal(t, "gobl-lookup", cfg.CouchDatabase)
	assert.Equal(t, "https://lookup.example", cfg.PublicBaseURL)

	// Assembled URL uses the defaults for scheme/port and encodes the
	// password's special characters.
	u := cfg.CouchDBURL()
	assert.Equal(t, "http://lookup:s3cr3t%2Fp%40ss@couchdb-svc.default:5984", u)

	// Redacted form drops the credentials — safe for logging.
	assert.Equal(t, "http://couchdb-svc.default:5984", cfg.CouchDBRedacted())
}

func TestCouchURLTakesPrecedence(t *testing.T) {
	cfg := config.Config{
		CouchURL:  "http://admin:pass@localhost:5984",
		CouchHost: "ignored.example",
	}
	assert.Equal(t, "http://admin:pass@localhost:5984", cfg.CouchDBURL())
	assert.Equal(t, "http://localhost:5984", cfg.CouchDBRedacted())
}

func TestCouchDBURLEmptyWithoutHostOrURL(t *testing.T) {
	assert.Empty(t, config.Config{}.CouchDBURL())
	assert.Empty(t, config.Config{}.CouchDBRedacted())
}

func TestCouchDBURLUsernameOnly(t *testing.T) {
	cfg := config.Config{CouchScheme: "https", CouchHost: "db.example", CouchPort: "6984", CouchUsername: "u"}
	assert.Equal(t, "https://u@db.example:6984", cfg.CouchDBURL())
}

func TestHTTPPortPrecedence(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		assert.Equal(t, config.DefaultHTTPPort, config.FromEnv().HTTPPort)
	})
	t.Run("PORT", func(t *testing.T) {
		t.Setenv("PORT", "8080")
		assert.Equal(t, 8080, config.FromEnv().HTTPPort)
	})
	t.Run("HTTP_PORT wins over PORT", func(t *testing.T) {
		t.Setenv("PORT", "8080")
		t.Setenv("HTTP_PORT", "9090")
		assert.Equal(t, 9090, config.FromEnv().HTTPPort)
	})
}

func TestEnvBool(t *testing.T) {
	assert.False(t, config.EnvBool("LOOKUP_MISSING_VAR", false))
	assert.True(t, config.EnvBool("LOOKUP_MISSING_VAR", true))
	t.Setenv("LOOKUP_FLAG", "true")
	assert.True(t, config.EnvBool("LOOKUP_FLAG", false))
	t.Setenv("LOOKUP_FLAG", "0")
	assert.False(t, config.EnvBool("LOOKUP_FLAG", true))
	t.Setenv("LOOKUP_FLAG", "garbage")
	assert.True(t, config.EnvBool("LOOKUP_FLAG", true), "unparseable falls back")
}

func TestEnv(t *testing.T) {
	assert.Equal(t, "fallback", config.Env("LOOKUP_MISSING_VAR", "fallback"))
	t.Setenv("LOOKUP_SET", "value")
	assert.Equal(t, "value", config.Env("LOOKUP_SET", "fallback"))
	t.Setenv("LOOKUP_SET", "")
	assert.Equal(t, "fallback", config.Env("LOOKUP_SET", "fallback"), "empty treated as unset")
}
