package documentstore

import (
	"encoding/base64"
	"strings"
	"time"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"
)

// Store backends.
const (
	StoreBackendPostgres = "postgres"
	StoreBackendMemory   = "memory"
)

// Blob (byte) backends.
const (
	BlobBackendS3     = "s3"
	BlobBackendMemory = "memory"
)

// Configuration is the document-store service configuration: the platform base
// config, the inbound go-authbyte DPoP validation config, the metadata store DSN,
// the encrypted S3 blob store + KMS, the 24h retention clock, and the GDPR-audit
// (GDPR access) audit client. document-store does NOT call eparaksts-signer — the
// user-facing DSS validate/archive is the Signing Orchestrator's.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth is the inbound DPoP validation config (AUTH_ISSUER_URL /
	// SERVICE_AUDIENCE=svc:document / …). Inbound callers are the Signing
	// Orchestrator + Portal-API + preview, presenting svc:document service tokens.
	Auth *authclient.Configuration `mapstructure:"auth"`

	// StoreDSN selects + configures the PostgreSQL metadata backend (the `document`
	// schema reached via SECURITY DEFINER procedures under the EXECUTE-only
	// `document_public` role). When set it is used; otherwise the in-memory backend
	// is used (development/test only). Source it from Vault in production.
	StoreDSN string `mapstructure:"document_store_dsn"`

	// MaxFileBytes caps each uploaded blob. Required, > 0. Keep compatible with the
	// signing path's body limit.
	MaxFileBytes int64 `mapstructure:"max_file_bytes" validate:"required,gt=0"`

	// --- Encrypted byte store: S3-API object storage (MinIO/Scality) ---
	// Coded to the S3 API via minio-go (the platform object-storage standard, not a
	// vendor SDK). When S3Endpoint + S3Bucket are set the S3 backend is used;
	// otherwise an in-memory blob store backs dev/test.
	S3Endpoint  string `mapstructure:"s3_endpoint"` // host[:port], no scheme
	S3AccessKey string `mapstructure:"s3_access_key"`
	S3SecretKey string `mapstructure:"s3_secret_key"`
	S3UseSSL    bool   `mapstructure:"s3_use_ssl"`
	S3Bucket    string `mapstructure:"s3_bucket"`
	S3Prefix    string `mapstructure:"s3_prefix"` // optional key prefix, e.g. "document/"

	// --- KMS envelope encryption ---
	// KMSMasterKey is the base64 (std) 32-byte AES-256 master key the dev "local
	// KMS" uses to wrap per-object data keys (envelope encryption). Empty → an
	// ephemeral dev key is generated at boot (bytes do NOT survive a restart — dev
	// only). Production swaps the local provider for Vault transit / AWS KMS behind
	// the same kms.KMS seam and sources this from Vault.
	KMSMasterKey string `mapstructure:"document_kms_master_key"`

	// --- 24h TTL (B2) — a launch invariant; the service owns this clock ---
	RetentionTTL           time.Duration `mapstructure:"document_retention_ttl" validate:"required,gt=0"`
	RetentionSweepInterval time.Duration `mapstructure:"document_retention_sweep_interval" validate:"required,gt=0"`
	RetentionSweepBatch    int           `mapstructure:"document_retention_sweep_batch" validate:"gte=0"`
	// HistoryRetention is how long a terminal chain's metadata record stays
	// readable as history after its storage is destroyed; older records are
	// erased by the sweep (data minimization). Zero disables the erasure.
	HistoryRetention time.Duration `mapstructure:"document_history_retention" validate:"gte=0"`

	// --- Outbound service-client identity ---
	// SERVICE_CLIENT_ID/SECRET authenticate this service's outbound DPoP service
	// tokens (the access-audit Poster, aud svc:access-audit). AuditIssuerURL points
	// the token mint at the in-network auth address (the `iss` stays Auth.IssuerURL).
	ServiceClientID     string `mapstructure:"service_client_id"`
	ServiceClientSecret string `mapstructure:"service_client_secret"`
	AuditIssuerURL      string `mapstructure:"audit_issuer_url" validate:"omitempty,url"`

	// --- GDPR-audit (GDPR personal-data access) → access-audit (optional) ---
	AccessAuditURL       string `mapstructure:"access_audit_url" validate:"omitempty,url"`
	AccessAuditAudience  string `mapstructure:"access_audit_audience"`
	AccessAuditScope     string `mapstructure:"access_audit_scope"`
	AccessAuditOutboxDir string `mapstructure:"access_audit_outbox_dir"`

	// --- Optional malware scan on user-facing uploads (deployment seam) ---
	// ClamAVEndpoint is a clamd host:port. When set, every user-facing upload
	// is scanned (INSTREAM) after the document gate and rejected on a FOUND
	// verdict; when empty the scan is skipped entirely. Scan availability is
	// fail-open: an unreachable scanner logs a warning and admits the upload.
	ClamAVEndpoint string `mapstructure:"clamav_endpoint"`

	// --- Document domain events (eIDAS-audit material events feed the Orchestrator) ---
	// The Document Service PUBLISHES document.uploaded / document.deleted to the
	// broker; the Signing Orchestrator is the eIDAS-audit producer that lands material
	// events on the eidas-audit chain. The Document Service does NOT
	// write the eidas_audit chain directly. Broker connection comes from BROKER_URL
	// (BaseConfiguration.Broker); without it events go to the dev log transport.
	DocumentEventsTopic string `mapstructure:"document_events_topic"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)

	// Upload + retention defaults.
	v.SetDefault("max_file_bytes", 25*1024*1024) // 25 MiB
	v.SetDefault("document_retention_ttl", 24*time.Hour)
	v.SetDefault("document_retention_sweep_interval", 15*time.Minute)
	v.SetDefault("document_retention_sweep_batch", 500)
	v.SetDefault("document_history_retention", 90*24*time.Hour)
	_ = v.BindEnv("document_history_retention", "DOCUMENT_HISTORY_RETENTION")

	// Dev-only user-token concession (off by default).

	// Metadata store.
	_ = v.BindEnv("document_store_dsn", "DOCUMENT_STORE_DSN")
	_ = v.BindEnv("max_file_bytes", "MAX_FILE_BYTES")
	_ = v.BindEnv("document_retention_ttl", "DOCUMENT_RETENTION_TTL")
	_ = v.BindEnv("document_retention_sweep_interval", "DOCUMENT_RETENTION_SWEEP_INTERVAL")
	_ = v.BindEnv("document_retention_sweep_batch", "DOCUMENT_RETENTION_SWEEP_BATCH")

	// S3 blob store.
	v.SetDefault("s3_use_ssl", false)
	loadSecret(v, "s3_secret_key", "S3_SECRET_KEY")
	_ = v.BindEnv("s3_endpoint", "S3_ENDPOINT")
	_ = v.BindEnv("s3_access_key", "S3_ACCESS_KEY")
	_ = v.BindEnv("s3_secret_key", "S3_SECRET_KEY")
	_ = v.BindEnv("s3_use_ssl", "S3_USE_SSL")
	_ = v.BindEnv("s3_bucket", "S3_BUCKET")
	_ = v.BindEnv("s3_prefix", "S3_PREFIX")

	// KMS.
	loadSecret(v, "document_kms_master_key", "DOCUMENT_KMS_MASTER_KEY")
	_ = v.BindEnv("document_kms_master_key", "DOCUMENT_KMS_MASTER_KEY")

	// Outbound service-client identity.
	v.SetDefault("service_client_id", "svc:document")
	loadSecret(v, "service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv("service_client_id", "SERVICE_CLIENT_ID")
	_ = v.BindEnv("service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv("audit_issuer_url", "AUDIT_ISSUER_URL")

	// GDPR-audit — off until ACCESS_AUDIT_URL is set.
	v.SetDefault("access_audit_audience", "svc:access-audit")
	v.SetDefault("access_audit_scope", "access-audit:write")
	_ = v.BindEnv("access_audit_url", "ACCESS_AUDIT_URL")
	_ = v.BindEnv("access_audit_audience", "ACCESS_AUDIT_AUDIENCE")
	_ = v.BindEnv("access_audit_scope", "ACCESS_AUDIT_SCOPE")
	_ = v.BindEnv("access_audit_outbox_dir", "ACCESS_AUDIT_OUTBOX_DIR")

	// Optional malware scan — off until CLAMAV_ENDPOINT is set.
	_ = v.BindEnv("clamav_endpoint", "CLAMAV_ENDPOINT")

	// Document domain events.
	v.SetDefault("document_events_topic", "document.events")
	_ = v.BindEnv("document_events_topic", "DOCUMENT_EVENTS_TOPIC")

}

// Validate validates the full configuration tree.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := c.Auth.Validate(valid); err != nil {
		return err
	}

	return valid.Struct(c)
}

// StoreBackend derives the metadata backend from configuration.
func (c *Configuration) StoreBackend() string {
	if strings.TrimSpace(c.StoreDSN) != "" {
		return StoreBackendPostgres
	}

	return StoreBackendMemory
}

// BlobBackend derives the byte backend from configuration.
func (c *Configuration) BlobBackend() string {
	if strings.TrimSpace(c.S3Endpoint) != "" && strings.TrimSpace(c.S3Bucket) != "" {
		return BlobBackendS3
	}

	return BlobBackendMemory
}

// AccessAuditEnabled reports whether GDPR-audit is wired.
func (c *Configuration) AccessAuditEnabled() bool {
	return strings.TrimSpace(c.AccessAuditURL) != ""
}

// OutboundEnabled reports whether an outbound DPoP service call is configured
// (the access-audit Poster). document-store has no other outbound service call.
func (c *Configuration) OutboundEnabled() bool {
	return c.AccessAuditEnabled()
}

// auditIssuer returns the issuer base for the outbound service-token mint.
func (c *Configuration) auditIssuer() string {
	if u := strings.TrimSpace(c.AuditIssuerURL); u != "" {
		return u
	}

	return c.Auth.IssuerURL
}

// OutboundAuthClientConfig builds the OUTBOUND auth-client config: it reuses the
// inbound Auth settings and adds this service's client-credentials + the
// (optional) issuer override. The outbound client serves the access-audit Poster
// (aud svc:access-audit).
func (c *Configuration) OutboundAuthClientConfig() *authclient.Configuration {
	cfg := *c.Auth // copy the validated inbound config
	cfg.IssuerURL = c.auditIssuer()
	cfg.ServiceClientID = c.ServiceClientID
	cfg.ServiceClientSecret = c.ServiceClientSecret

	return &cfg
}

// GDPRConfig builds the go-gdpr-audit client configuration.
func (c *Configuration) GDPRConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:         c.AccessAuditURL,
		Audience:         c.AccessAuditAudience,
		Scope:            c.AccessAuditScope,
		Timeout:          gdpr.DefaultTimeout,
		OutboxCapacity:   gdpr.DefaultOutboxCapacity,
		MaxRetries:       gdpr.DefaultMaxRetries,
		RetryBackoff:     gdpr.DefaultRetryBackoff,
		BreakerThreshold: gdpr.DefaultBreakerThreshold,
		BreakerCooldown:  gdpr.DefaultBreakerCooldown,
	}
}

// MasterKeyBytes decodes the base64 (std) KMS master key, or returns nil when
// unset (the local KMS then generates an ephemeral dev key).
func (c *Configuration) MasterKeyBytes() ([]byte, error) {
	if strings.TrimSpace(c.KMSMasterKey) == "" {
		return nil, nil
	}

	return base64.StdEncoding.DecodeString(strings.TrimSpace(c.KMSMasterKey))
}

// loadSecret resolves a secret from the secret store (Vault agent → <NAME>_FILE)
// and registers it as a default so an explicit env value still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}
