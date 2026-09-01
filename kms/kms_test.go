package kms

import (
	"bytes"
	"testing"
)

func TestLocalEnvelopeRoundTrip(t *testing.T) {
	k, ephemeral, err := NewLocal(nil)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	if !ephemeral {
		t.Fatalf("expected an ephemeral key when none supplied")
	}

	plain, wrapped, err := k.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(plain) != 32 {
		t.Fatalf("data key length = %d, want 32", len(plain))
	}
	if bytes.Equal(plain, wrapped) {
		t.Fatalf("wrapped key must not equal the plaintext key")
	}

	got, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("unwrapped key != original")
	}

	// Seal/Open round-trip with the plaintext data key.
	msg := []byte("the quick brown fox — confidential bytes")
	sealed, err := Seal(plain, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, msg) {
		t.Fatalf("ciphertext must not contain the plaintext")
	}
	opened, err := Open(plain, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatalf("opened != original")
	}
}

func TestLocalFixedMasterKeyDurable(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)

	k1, ephemeral, err := NewLocal(master)
	if err != nil || ephemeral {
		t.Fatalf("NewLocal(master): err=%v ephemeral=%v", err, ephemeral)
	}
	plain, wrapped, err := k1.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}

	// A second instance built from the SAME master key can unwrap (durability).
	k2, _, err := NewLocal(master)
	if err != nil {
		t.Fatalf("NewLocal(master) again: %v", err)
	}
	got, err := k2.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap across instances: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("cross-instance unwrap mismatch")
	}
}
