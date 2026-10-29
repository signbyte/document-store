package documentstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// bound reads the configuration from the environment the way the service does at start.
func bound(t *testing.T) *Configuration {
	t.Helper()

	c := NewConfiguration()
	v := viper.New()
	c.Bind("", v)
	if err := v.Unmarshal(c); err != nil {
		t.Fatal(err)
	}

	return c
}

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// The connection string carries the database role's password, so it may arrive
// as a file the secret store's agent writes (DOCUMENT_STORE_DSN_FILE).
func TestTheStoreAddressIsReadFromAFile(t *testing.T) {
	t.Setenv("DOCUMENT_STORE_DSN_FILE", writeSecretFile(t, "postgres://document_public:pw@db:5432/fleet\n"))

	if got := bound(t).StoreDSN; got != "postgres://document_public:pw@db:5432/fleet" {
		t.Fatalf("store DSN = %q, want the file's content", got)
	}
}

// An explicit environment value still wins over the file.
func TestTheStoreAddressFromTheEnvironmentWinsOverTheFile(t *testing.T) {
	t.Setenv("DOCUMENT_STORE_DSN_FILE", writeSecretFile(t, "postgres://from-file"))
	t.Setenv("DOCUMENT_STORE_DSN", "postgres://from-env")

	if got := bound(t).StoreDSN; got != "postgres://from-env" {
		t.Fatalf("store DSN = %q, want the environment value", got)
	}
}

// The blob store's access key is half of its credential, so it comes from a file too.
func TestTheBlobAccessKeyIsReadFromAFile(t *testing.T) {
	t.Setenv("S3_ACCESS_KEY_FILE", writeSecretFile(t, "AKIAEXAMPLE\n"))

	if got := bound(t).S3AccessKey; got != "AKIAEXAMPLE" {
		t.Fatalf("S3 access key = %q, want the file's content", got)
	}
}
