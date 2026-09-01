package documentstore

import "testing"

// TestTestAppWiresDevelopmentDefaults exercises App.New/init end to end (the
// in-memory store/blob, the ephemeral local KMS, the dev-off auth path, the
// log domain-event transport, and the retention task registration) the way
// every other package's tests already do via TestApp — this just makes sure
// the wiring itself is covered from within its own package.
func TestTestAppWiresDevelopmentDefaults(t *testing.T) {
	app := TestApp(t)

	if app.Documents() == nil {
		t.Fatal("Documents() = nil")
	}
	if app.Store() == nil {
		t.Fatal("Store() = nil")
	}
	if app.Blob() == nil {
		t.Fatal("Blob() = nil")
	}
	if app.Audit() == nil {
		t.Fatal("Audit() = nil")
	}
	if app.AuthMiddleware() == nil {
		t.Fatal("AuthMiddleware() = nil")
	}

	cfg := app.Config()
	if cfg.StoreBackend() != StoreBackendMemory {
		t.Fatalf("StoreBackend() = %q, want %q (no DOCUMENT_STORE_DSN)", cfg.StoreBackend(), StoreBackendMemory)
	}
	if cfg.BlobBackend() != BlobBackendMemory {
		t.Fatalf("BlobBackend() = %q, want %q (no S3_ENDPOINT)", cfg.BlobBackend(), BlobBackendMemory)
	}
}

func TestConfigPanicsBeforeLoaded(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Config() on an unloaded app must panic")
		}
	}()
	(&App{}).Config()
}
