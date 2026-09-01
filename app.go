// Package documentstore is the eSignature-Portal document-store service: the
// platform's single source of truth for document BYTES and HASHES. It owns
// ingest, the canonical SHA-256, envelope-encrypted S3 storage with a 24h TTL,
// ASiC-E assembly/completion via the embedded gmb-lib/go-asice library (integrity
// self-checked locally with asice.CheckReferences — no DSS call), and retention.
// It is a pure byte/hash supplier: the user-facing DSS validate +
// archive-timestamp are owned by the Signing Orchestrator, which fetches bytes
// from here. Metadata lives in the `document` schema, reached only through
// SECURITY DEFINER procedures under the EXECUTE-only document_public role.
//
// All cross-cutting concerns (logging + redaction, OpenTelemetry tracing,
// correlation) come from go-platform-kit's platform.Setup — never wired
// per-service.
package documentstore

import (
	"fmt"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-platform-kit/broker/natsbroker"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/document-store/audit"
	"github.com/signbyte/document-store/documents"
	"github.com/signbyte/document-store/kms"
	"github.com/signbyte/document-store/s3"
	"github.com/signbyte/document-store/store"
	"github.com/signbyte/document-store/tasks"
)

// App is the document-store application container.
type App struct {
	*azugo.App

	config *Configuration

	store store.Store
	blob  s3.Store
	kms   kms.KMS
	docs  *documents.Service

	authClient *authclient.Client
	authMW     azugo.RequestHandlerFunc

	// Outbound (set only when GDPR-audit / access-audit is configured).
	outboundClient *authclient.Client
	gdprAudit      *gdpr.Client

	audit *audit.Recorder
}

// New constructs the application.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Document Store Service",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	// Platform glue FIRST: logging + redaction, OpenTelemetry tracing, correlation.
	if err := platform.Setup(a.App, platform.Options{Config: cfg.BaseConfiguration}); err != nil {
		return err
	}

	// Metadata store: `document` schema via the EXECUTE-only role, or in-memory (dev).
	var err error
	switch cfg.StoreBackend() {
	case StoreBackendPostgres:
		a.store, err = store.NewPostgres(a.BackgroundContext(), cfg.StoreDSN)
		if err != nil {
			return err
		}
	default:
		a.Log().Warn("no store DSN configured (DOCUMENT_STORE_DSN) — using in-memory metadata store; documents will NOT survive restarts (development only)")
		a.store = store.NewMemory()
	}

	// Encrypted byte store: S3-API object storage, or in-memory (dev).
	switch cfg.BlobBackend() {
	case BlobBackendS3:
		a.blob, err = s3.New(s3.Options{
			Endpoint:  cfg.S3Endpoint,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			UseSSL:    cfg.S3UseSSL,
			Bucket:    cfg.S3Bucket,
			Prefix:    cfg.S3Prefix,
		})
		if err != nil {
			return err
		}
	default:
		a.Log().Warn("no S3 configured (S3_ENDPOINT/S3_BUCKET) — using in-memory blob store; bytes will NOT survive restarts (development only)")
		a.blob = s3.NewMemory()
	}

	// KMS envelope encryption (local provider; swap for Vault/AWS in prod).
	master, err := cfg.MasterKeyBytes()
	if err != nil {
		return fmt.Errorf("document-store: invalid DOCUMENT_KMS_MASTER_KEY (expect base64 32 bytes): %w", err)
	}
	localKMS, ephemeral, err := kms.NewLocal(master)
	if err != nil {
		return fmt.Errorf("document-store: kms: %w", err)
	}
	if ephemeral {
		a.Log().Warn("no DOCUMENT_KMS_MASTER_KEY configured — generated an EPHEMERAL master key; stored bytes become undecryptable after a restart (development only)")
	}
	a.kms = localKMS

	a.docs = documents.New(a.store, a.blob, a.kms, cfg.RetentionTTL)

	// Inbound service authentication (go-authbyte DPoP): callers present
	// svc:document service tokens (the delegated on-behalf tokens included).
	a.authClient, err = authclient.New(cfg.Auth)
	if err != nil {
		return fmt.Errorf("document-store: auth client: %w", err)
	}
	a.authMW = a.authClient.Authenticate()

	// Outbound DPoP service client — serves the access-audit Poster (aud
	// svc:access-audit). document-store does NOT call eparaksts-signer: the
	// user-facing DSS validate/archive is the Signing Orchestrator's call
	//.
	if cfg.OutboundEnabled() {
		a.outboundClient, err = authclient.New(cfg.OutboundAuthClientConfig())
		if err != nil {
			return fmt.Errorf("document-store: outbound auth client: %w", err)
		}
	}

	// NIS2-audit emitter (always) + GDPR-audit client (optional) + domain-event
	// publisher (broker when BROKER_URL is set, else the dev log transport).
	// Built with the service logger: the retention sweep emits with no request whose
	// logger it could borrow.
	secEmitter := secevents.NewEmitter(secevents.NewLogSinkFor(a.Log()))

	var gc *gdpr.Client
	if cfg.AccessAuditEnabled() {
		var outbox gdpr.Outbox
		if dir := cfg.AccessAuditOutboxDir; dir != "" {
			ob, err := gdpr.NewFileOutbox(dir, gdpr.DefaultOutboxCapacity)
			if err != nil {
				return fmt.Errorf("document-store: audit outbox: %w", err)
			}
			outbox = ob
		}

		gc, err = gdpr.New(
			cfg.GDPRConfig(),
			newAccessAuditPoster(a.outboundClient, cfg.AccessAuditURL, cfg.AccessAuditAudience, cfg.AccessAuditScope),
			gdpr.Options{Outbox: outbox, Logger: a.Log()},
		)
		if err != nil {
			return fmt.Errorf("document-store: gdpr-audit client: %w", err)
		}
		a.gdprAudit = gc

		if err := a.AddTask(audit.NewDrainTask(gc)); err != nil {
			return fmt.Errorf("document-store: gdpr drain task: %w", err)
		}
	} else {
		a.Log().Warn("ACCESS_AUDIT_URL not set — GDPR (GDPR-audit) access records will NOT be posted (development); NIS2-audit security telemetry still emits")
	}

	var domainPub *broker.Publisher
	var domainTransport broker.Transport
	if cfg.Broker != nil && cfg.Broker.URL != "" {
		conn, err := natsbroker.Connect(natsbroker.Config{
			URL:     cfg.Broker.URL,
			TLSCert: cfg.Broker.TLSCert,
			TLSKey:  cfg.Broker.TLSKey,
			TLSCA:   cfg.Broker.TLSCA,
			Name:    cfg.ServiceName,
		})
		if err != nil {
			return fmt.Errorf("document-store: broker connect: %w", err)
		}
		domainTransport = natsbroker.NewTransport(conn)
		a.Log().Info("document domain events → NATS JetStream",
			zap.String("broker_url", cfg.Broker.URL), zap.String("topic", cfg.DocumentEventsTopic))
	} else {
		domainTransport = newLogTransport(a.Log())
		a.Log().Warn("BROKER_URL unset — document domain events go to the dev log transport only (the Signing Orchestrator's eIDAS-audit feed is not durable); set BROKER_URL to publish")
	}
	domainPub = broker.NewPublisher(domainTransport, cfg.ServiceName)

	a.audit = audit.New(secEmitter, gc, domainPub, cfg.DocumentEventsTopic, a.Log())

	// Retention sweep (24h TTL): destroys expired non-hold bytes + flips status.
	return a.AddTask(tasks.NewRetentionTask(tasks.RetentionConfig{
		Service:     a.docs,
		Audit:       a.audit,
		Interval:    cfg.RetentionSweepInterval,
		Batch:       cfg.RetentionSweepBatch,
		HistoryKeep: cfg.HistoryRetention,
		Logger:      a.Log(),
	}))
}

// Start verifies backend connectivity (non-fatal) then starts the server + tasks.
func (a *App) Start() error {
	if err := a.store.Ping(a.BackgroundContext()); err != nil {
		a.Log().Warn("document store not reachable at start — readiness will report not-ready until it recovers", zap.Error(err))
	}
	if err := a.blob.Ping(a.BackgroundContext()); err != nil {
		a.Log().Warn("blob store not reachable at start — readiness will report not-ready until it recovers", zap.Error(err))
	}

	return a.App.Start()
}

// Stop releases backend resources, then stops the server.
func (a *App) Stop() {
	if a.store != nil {
		a.store.Close()
	}
	a.App.Stop()
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Documents returns the document domain service.
func (a *App) Documents() *documents.Service { return a.docs }

// Store returns the metadata store (readiness checks).
func (a *App) Store() store.Store { return a.store }

// Blob returns the byte store (readiness checks).
func (a *App) Blob() s3.Store { return a.blob }

// Audit returns the audit recorder.
func (a *App) Audit() *audit.Recorder { return a.audit }

// AuthMiddleware returns the inbound service-authentication middleware.
func (a *App) AuthMiddleware() azugo.RequestHandlerFunc { return a.authMW }

// SetAuthMiddleware overrides the inbound auth middleware (test use only).
func (a *App) SetAuthMiddleware(mw azugo.RequestHandlerFunc) { a.authMW = mw }
