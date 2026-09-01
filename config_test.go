package documentstore

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/gmb-lib/go-authbyte/authclient"
)

func TestStoreBackend(t *testing.T) {
	if got := (&Configuration{}).StoreBackend(); got != StoreBackendMemory {
		t.Fatalf("StoreBackend() = %q, want %q (no DSN)", got, StoreBackendMemory)
	}
	if got := (&Configuration{StoreDSN: " postgres://x "}).StoreBackend(); got != StoreBackendPostgres {
		t.Fatalf("StoreBackend() = %q, want %q", got, StoreBackendPostgres)
	}
}

func TestBlobBackend(t *testing.T) {
	if got := (&Configuration{}).BlobBackend(); got != BlobBackendMemory {
		t.Fatalf("BlobBackend() = %q, want %q (nothing set)", got, BlobBackendMemory)
	}
	if got := (&Configuration{S3Endpoint: "minio:9000"}).BlobBackend(); got != BlobBackendMemory {
		t.Fatalf("BlobBackend() = %q, want %q (endpoint without bucket)", got, BlobBackendMemory)
	}
	if got := (&Configuration{S3Endpoint: "minio:9000", S3Bucket: "docs"}).BlobBackend(); got != BlobBackendS3 {
		t.Fatalf("BlobBackend() = %q, want %q", got, BlobBackendS3)
	}
}

func TestAccessAuditEnabled(t *testing.T) {
	if (&Configuration{}).AccessAuditEnabled() {
		t.Fatal("AccessAuditEnabled() = true, want false without ACCESS_AUDIT_URL")
	}
	if !(&Configuration{AccessAuditURL: "http://access-audit.local"}).AccessAuditEnabled() {
		t.Fatal("AccessAuditEnabled() = false, want true with ACCESS_AUDIT_URL set")
	}
}

func TestOutboundEnabledMirrorsAccessAudit(t *testing.T) {
	c := &Configuration{}
	if c.OutboundEnabled() != c.AccessAuditEnabled() {
		t.Fatal("OutboundEnabled() must mirror AccessAuditEnabled()")
	}
	c.AccessAuditURL = "http://access-audit.local"
	if !c.OutboundEnabled() {
		t.Fatal("OutboundEnabled() = false once access-audit is configured")
	}
}

func TestMasterKeyBytes(t *testing.T) {
	b, err := (&Configuration{}).MasterKeyBytes()
	if err != nil || b != nil {
		t.Fatalf("MasterKeyBytes() = %v, %v; want nil, nil when unset", b, err)
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	encoded := base64.StdEncoding.EncodeToString(key)
	got, err := (&Configuration{KMSMasterKey: " " + encoded + " "}).MasterKeyBytes()
	if err != nil {
		t.Fatalf("MasterKeyBytes(): %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("MasterKeyBytes() = %x, want %x", got, key)
	}

	if _, err := (&Configuration{KMSMasterKey: "not-valid-base64!!"}).MasterKeyBytes(); err == nil {
		t.Fatal("MasterKeyBytes() with invalid base64 must error")
	}
}

func TestAuditIssuerFallsBackToAuthIssuer(t *testing.T) {
	cfg := &Configuration{Auth: &authclient.Configuration{IssuerURL: "http://auth.local"}}
	if got := cfg.auditIssuer(); got != "http://auth.local" {
		t.Fatalf("auditIssuer() = %q, want %q (fallback to Auth.IssuerURL)", got, "http://auth.local")
	}

	cfg.AuditIssuerURL = "http://audit.local"
	if got := cfg.auditIssuer(); got != "http://audit.local" {
		t.Fatalf("auditIssuer() = %q, want %q (explicit override)", got, "http://audit.local")
	}
}

func TestOutboundAuthClientConfigCopiesInboundAndAddsCredentials(t *testing.T) {
	cfg := &Configuration{
		Auth:                &authclient.Configuration{IssuerURL: "http://auth.local", ServiceAudience: "svc:document"},
		ServiceClientID:     "svc:document",
		ServiceClientSecret: "s3cr3t",
	}

	out := cfg.OutboundAuthClientConfig()

	if out == cfg.Auth {
		t.Fatal("OutboundAuthClientConfig() must return a copy, not alias the inbound config")
	}
	if out.IssuerURL != "http://auth.local" {
		t.Fatalf("IssuerURL = %q, want %q", out.IssuerURL, "http://auth.local")
	}
	if out.ServiceClientID != "svc:document" || out.ServiceClientSecret != "s3cr3t" {
		t.Fatalf("outbound credentials not applied: %+v", out)
	}
	// The inbound config must be untouched by building the outbound copy.
	if cfg.Auth.ServiceClientID != "" {
		t.Fatalf("inbound Auth.ServiceClientID mutated: %q", cfg.Auth.ServiceClientID)
	}
}

func TestGDPRConfigMapsFields(t *testing.T) {
	cfg := &Configuration{
		AccessAuditURL:      "http://access-audit.local",
		AccessAuditAudience: "svc:access-audit",
		AccessAuditScope:    "access-audit:write",
	}

	g := cfg.GDPRConfig()

	if g.Endpoint != cfg.AccessAuditURL || g.Audience != cfg.AccessAuditAudience || g.Scope != cfg.AccessAuditScope {
		t.Fatalf("GDPRConfig() = %+v, want fields sourced from Configuration", g)
	}
}
