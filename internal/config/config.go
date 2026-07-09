// Package config defines the runtime configuration for the lookup
// service. Values are resolved from environment variables (the
// mechanism the cluster uses to inject config and secrets) and may be
// overridden by the command-line flags in cmd/gobl.lookup.
package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/invopop/couch"
)

// Config holds the options shared by the serve and verify commands.
//
// CouchDB may be configured in two ways: a single connection URL
// (CouchURL, from --couchdb / COUCHDB_URL — convenient for local dev),
// or the split parts (CouchScheme/Host/Port/Username/Password, from the
// COUCHDB_* env vars — the cluster convention, so the password can be
// injected from a secret separately). CouchURL, when set, wins.
type Config struct {
	// ConfigDir is the directory holding the lookup identity
	// (private.jwk + party.json + keys/).
	ConfigDir string

	// CouchURL is an explicit full CouchDB connection URL. When set it
	// takes precedence over the split Couch* fields.
	CouchURL string
	// Split CouchDB connection parts (used when CouchURL is empty).
	CouchScheme   string
	CouchHost     string
	CouchPort     string
	CouchUsername string
	CouchPassword string
	// CouchDatabase is the CouchDB database name.
	CouchDatabase string

	// HTTPPort is the port the serve command listens on.
	HTTPPort int
	// PublicBaseURL is the canonical https URL used to build
	// /parties/<uuid> discovery links. Empty defaults to
	// https://<domain>.
	PublicBaseURL string
	// ShutdownTimeout bounds graceful shutdown of the HTTP server.
	ShutdownTimeout time.Duration
	// JSONLogs switches operator logs from text to JSON.
	JSONLogs bool
}

// FromEnv builds a Config from environment variables, applying the
// service defaults. Command flags layer on top of this (flag set →
// overrides env; flag unset → keeps the env/default value).
func FromEnv() Config {
	return Config{
		ConfigDir: Env("CONFIG_DIR", ""),

		CouchURL:      Env("COUCHDB_URL", ""),
		CouchScheme:   Env("COUCHDB_SCHEME", "http"),
		CouchHost:     Env("COUCHDB_HOST", ""),
		CouchPort:     Env("COUCHDB_PORT", "5984"),
		CouchUsername: Env("COUCHDB_USERNAME", "admin"),
		CouchPassword: Env("COUCHDB_PASSWORD", ""),
		CouchDatabase: Env("COUCHDB_DATABASE", "gobl-lookup"),

		HTTPPort:        httpPortFromEnv(),
		PublicBaseURL:   Env("PUBLIC_BASE_URL", ""),
		ShutdownTimeout: 10 * time.Second,
		JSONLogs:        EnvBool("LOG_JSON", false),
	}
}

// CouchDBURL resolves the CouchDB connection URL: the explicit
// CouchURL if set, otherwise one assembled from the split Couch* parts.
// Returns "" when neither a URL nor a host is configured.
func (c Config) CouchDBURL() string {
	if c.CouchURL != "" {
		return c.CouchURL
	}
	if c.CouchHost == "" {
		return ""
	}
	scheme := c.CouchScheme
	if scheme == "" {
		scheme = "http"
	}
	host := c.CouchHost
	if c.CouchPort != "" {
		host = net.JoinHostPort(c.CouchHost, c.CouchPort)
	}
	u := &url.URL{Scheme: scheme, Host: host}
	if c.CouchUsername != "" {
		if c.CouchPassword != "" {
			u.User = url.UserPassword(c.CouchUsername, c.CouchPassword)
		} else {
			u.User = url.User(c.CouchUsername)
		}
	}
	return u.String()
}

// CouchConfig builds a *couch.Config from the resolved connection. The
// database name (COUCHDB_DATABASE) is used as the couch prefix; the
// registrations repo opens the single database named by that prefix.
func (c Config) CouchConfig() (*couch.Config, error) {
	raw := c.CouchDBURL()
	if raw == "" {
		return nil, errors.New("config: no CouchDB connection configured")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	cc := &couch.Config{
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   u.Port(),
		Prefix: c.CouchDatabase,
	}
	if cc.Port == "" {
		cc.Port = "5984"
	}
	if u.User != nil {
		cc.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			cc.Password = pw
		}
	}
	return cc, nil
}

// CouchDBRedacted returns the resolved CouchDB URL with any credentials
// stripped — safe for logging.
func (c Config) CouchDBRedacted() string {
	raw := c.CouchDBURL()
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

// Env returns the value of the environment variable key, or fallback
// when it is unset or empty.
func Env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// EnvBool parses a boolean environment variable, falling back on unset
// or unparseable values.
func EnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// DefaultHTTPPort is the port the server listens on when neither
// HTTP_PORT/PORT nor --http-port is set. 8080 (not 80) so the
// unprivileged container user can bind it without extra capabilities.
const DefaultHTTPPort = 8080

// httpPortFromEnv resolves the listen port from HTTP_PORT, then PORT,
// then DefaultHTTPPort.
func httpPortFromEnv() int {
	for _, key := range []string{"HTTP_PORT", "PORT"} {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				return p
			}
		}
	}
	return DefaultHTTPPort
}
