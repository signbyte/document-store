// Package s3 is the encrypted-byte object store. Blobs are written/read by S3
// object key (the row's storage_ref). It is coded to the S3 API via minio-go —
// the platform object-storage standard, NOT a vendor SDK — exactly
// as trust-anchor/store/s3.go does. The bytes handed here are ALREADY
// envelope-encrypted by the kms package; this layer is content-agnostic.
package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Store is the blob persistence contract (one object per stored blob).
type Store interface {
	// Put writes data under key.
	Put(ctx context.Context, key string, data []byte) error
	// Get reads the object at key. It returns (nil, false, nil) when the object
	// does not exist.
	Get(ctx context.Context, key string) (data []byte, found bool, err error)
	// Delete removes the object at key (no error if it is already gone).
	Delete(ctx context.Context, key string) error
	// Ping verifies backend reachability for readiness checks.
	Ping(ctx context.Context) error
}

// S3 is the production blob store (MinIO/Scality via minio-go).
type S3 struct {
	client *minio.Client
	bucket string
	prefix string
}

// Options configures the S3 store.
type Options struct {
	Endpoint  string // host[:port], no scheme
	AccessKey string
	SecretKey string
	UseSSL    bool
	Bucket    string
	Prefix    string // optional key prefix, e.g. "document/"
}

// New connects the S3 store. It does not create the bucket — provisioning is an
// ops concern (the dev compose seeds it with a one-shot mc job).
func New(opts Options) (*S3, error) {
	client, err := minio.New(opts.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(opts.AccessKey, opts.SecretKey, ""),
		Secure: opts.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: client: %w", err)
	}
	prefix := opts.Prefix
	if prefix != "" && prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}

	return &S3{client: client, bucket: opts.Bucket, prefix: prefix}, nil
}

func (s *S3) key(k string) string { return s.prefix + k }

// Put writes the (already-encrypted) bytes under key.
func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.client.PutObject(ctx, s.bucket, s.key(key), bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("s3: put %s: %w", key, err)
	}

	return nil
}

// Get reads the object at key, returning found=false for a missing object.
func (s *S3) Get(ctx context.Context, key string) ([]byte, bool, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, s.key(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("s3: get %s: %w", key, err)
	}
	defer func() { _ = obj.Close() }()

	b, err := io.ReadAll(obj)
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.Code == "NoSuchKey" {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("s3: read %s: %w", key, err)
	}

	return b, true, nil
}

// Delete removes the object at key (idempotent).
func (s *S3) Delete(ctx context.Context, key string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, s.key(key), minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("s3: delete %s: %w", key, err)
	}

	return nil
}

// Ping verifies the bucket is reachable.
func (s *S3) Ping(ctx context.Context) error {
	if _, err := s.client.BucketExists(ctx, s.bucket); err != nil {
		return fmt.Errorf("s3: ping: %w", err)
	}

	return nil
}

// Memory is an in-memory blob store for development/tests (no S3 configured).
type Memory struct {
	mu   sync.Mutex
	objs map[string][]byte
}

// NewMemory returns an empty in-memory blob store.
func NewMemory() *Memory { return &Memory{objs: map[string][]byte{}} }

// Put stores a copy of data under key.
func (m *Memory) Put(_ context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := make([]byte, len(data))
	copy(cp, data)
	m.objs[key] = cp

	return nil
}

// Get returns a copy of the object, or found=false.
func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.objs[key]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)

	return cp, true, nil
}

// Delete removes the object (idempotent).
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.objs, key)

	return nil
}

// Ping always succeeds for the in-memory backend.
func (m *Memory) Ping(context.Context) error { return nil }
