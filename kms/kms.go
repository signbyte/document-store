// Package kms provides envelope encryption for stored document bytes:
//
// - GenerateDataKey returns a fresh random per-object data key (plaintext) plus
// its KMS-WRAPPED form. The wrapped form is what the metadata row keeps in
// encryption_key_ref; the plaintext key never leaves memory.
// - The object bytes are sealed with the plaintext data key (AES-256-GCM) by
// Seal; Open reverses it.
// - Unwrap recovers a plaintext data key from its wrapped form on read.
//
// The KMS interface is the seam: the dev "local" provider wraps data keys with an
// AES-256 master key held in process (from DOCUMENT_KMS_MASTER_KEY, or an
// ephemeral key in development). Production swaps in Vault transit / AWS KMS
// behind the same interface with no change to the storage layer.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// dataKeyLen is the per-object data-key length (AES-256).
const dataKeyLen = 32

// KMS wraps + unwraps per-object data keys (the "key-encryption key" half of
// envelope encryption). It does NOT see object content.
type KMS interface {
	// GenerateDataKey returns a fresh random data key and its wrapped form.
	GenerateDataKey() (plaintext, wrapped []byte, err error)
	// Unwrap recovers a plaintext data key from its wrapped form.
	Unwrap(wrapped []byte) (plaintext []byte, err error)
}

// Seal encrypts plaintext under a data key with AES-256-GCM, returning
// nonce||ciphertext. The data key must be 32 bytes (as produced by GenerateDataKey).
func Seal(dataKey, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("kms: seal nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal.
func Open(dataKey, blob []byte) ([]byte, error) {
	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("kms: ciphertext too short")
	}
	out, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("kms: open: %w", err)
	}

	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != dataKeyLen {
		return nil, fmt.Errorf("kms: data key must be %d bytes, got %d", dataKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kms: cipher: %w", err)
	}

	return cipher.NewGCM(block)
}

// Local is the dev/in-process KMS: it wraps data keys with an AES-256 master key
// using AES-256-GCM (the wrapped form is nonce||ciphertext). Swap for Vault
// transit / AWS KMS in production behind the KMS interface.
type Local struct {
	gcm cipher.AEAD
}

// NewLocal builds a Local KMS from a 32-byte master key. Pass nil to generate an
// ephemeral dev key (NOT durable across restarts — development only).
func NewLocal(master []byte) (*Local, bool, error) {
	ephemeral := false
	if len(master) == 0 {
		master = make([]byte, dataKeyLen)
		if _, err := io.ReadFull(rand.Reader, master); err != nil {
			return nil, false, fmt.Errorf("kms: ephemeral master key: %w", err)
		}
		ephemeral = true
	}
	if len(master) != dataKeyLen {
		return nil, false, fmt.Errorf("kms: master key must be %d bytes, got %d", dataKeyLen, len(master))
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, false, fmt.Errorf("kms: master cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, fmt.Errorf("kms: master gcm: %w", err)
	}

	return &Local{gcm: gcm}, ephemeral, nil
}

// GenerateDataKey returns a fresh 32-byte data key + its master-wrapped form.
func (l *Local) GenerateDataKey() (plaintext, wrapped []byte, err error) {
	plaintext = make([]byte, dataKeyLen)
	if _, err = io.ReadFull(rand.Reader, plaintext); err != nil {
		return nil, nil, fmt.Errorf("kms: data key: %w", err)
	}
	nonce := make([]byte, l.gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("kms: wrap nonce: %w", err)
	}
	wrapped = l.gcm.Seal(nonce, nonce, plaintext, nil)

	return plaintext, wrapped, nil
}

// Unwrap recovers the plaintext data key from its master-wrapped form.
func (l *Local) Unwrap(wrapped []byte) ([]byte, error) {
	ns := l.gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("kms: wrapped key too short")
	}
	out, err := l.gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("kms: unwrap: %w", err)
	}

	return out, nil
}
