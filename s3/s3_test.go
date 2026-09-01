package s3

import (
	"bytes"
	"context"
	"testing"
)

func TestMemoryPutGetRoundTrip(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	data := []byte("encrypted bytes")
	if err := m.Put(ctx, "key-1", data); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, found, err := m.Get(ctx, "key-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("Get: found = false, want true")
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Get = %q, want %q", got, data)
	}
}

func TestMemoryGetMissingKey(t *testing.T) {
	m := NewMemory()

	got, found, err := m.Get(context.Background(), "missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatal("Get: found = true for a missing key")
	}
	if got != nil {
		t.Fatalf("Get data = %v, want nil for a missing key", got)
	}
}

func TestMemoryPutStoresACopy(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	data := []byte("original")
	if err := m.Put(ctx, "key-1", data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data[0] = 'X' // mutate the caller's slice after Put

	got, _, err := m.Get(ctx, "key-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("Get = %q, want %q (Put must copy its input)", got, "original")
	}

	got[0] = 'Y' // mutate the returned slice
	got2, _, _ := m.Get(ctx, "key-1")
	if string(got2) != "original" {
		t.Fatalf("Get = %q, want %q (Get must return a copy)", got2, "original")
	}
}

func TestMemoryDeleteIsIdempotent(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	if err := m.Put(ctx, "key-1", []byte("bytes")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := m.Delete(ctx, "key-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.Delete(ctx, "key-1"); err != nil {
		t.Fatalf("Delete (again, already gone): %v", err)
	}

	if _, found, err := m.Get(ctx, "key-1"); err != nil || found {
		t.Fatalf("Get after delete: found=%v err=%v, want found=false err=nil", found, err)
	}
}

func TestMemoryPing(t *testing.T) {
	if err := NewMemory().Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestNewPrefixNormalization(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		want   string
	}{
		{"empty stays empty", "", ""},
		{"no trailing slash gets one", "document", "document/"},
		{"trailing slash is kept as-is", "document/", "document/"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := New(Options{Endpoint: "localhost:9000", AccessKey: "k", SecretKey: "s", Bucket: "b", Prefix: c.prefix})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if s.prefix != c.want {
				t.Fatalf("prefix = %q, want %q", s.prefix, c.want)
			}
			if s.bucket != "b" {
				t.Fatalf("bucket = %q, want %q", s.bucket, "b")
			}
		})
	}
}

func TestKeyAppliesPrefix(t *testing.T) {
	s, err := New(Options{Endpoint: "localhost:9000", AccessKey: "k", SecretKey: "s", Bucket: "b", Prefix: "document"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.key("abc"); got != "document/abc" {
		t.Fatalf("key(%q) = %q, want %q", "abc", got, "document/abc")
	}
}
