package response

import (
	"testing"
	"time"

	"github.com/signbyte/document-store/store"
)

func TestFromStoreMapsAllFields(t *testing.T) {
	retention := time.Now().Add(24 * time.Hour)
	created := time.Now().Add(-time.Hour)
	updated := time.Now()

	d := &store.Document{
		ID:                "doc-1",
		Owner:             "owner-1",
		TenantID:          "tenant-1",
		Kind:              "container",
		ParentID:          "parent-1",
		Filename:          "a.asice",
		StorageRef:        "should-not-leak",
		ContentHash:       "hash==",
		Mime:              "application/vnd.etsi.asic-e+zip",
		Size:              1234,
		Status:            "signed",
		EncryptionKeyRef:  "should-not-leak",
		PreservationClass: "b_lt",
		RetentionUntil:    retention,
		LegalHold:         true,
		InnerFiles: []store.ManifestFile{
			{Name: "content.txt", MediaType: "text/plain", Size: 42},
		},
		CreatedAt: created,
		UpdatedAt: updated,
	}

	got := FromStore(d)

	want := Document{
		ID:                "doc-1",
		Owner:             "owner-1",
		TenantID:          "tenant-1",
		Kind:              "container",
		ParentID:          "parent-1",
		Filename:          "a.asice",
		ContentHash:       "hash==",
		Mime:              "application/vnd.etsi.asic-e+zip",
		Size:              1234,
		Status:            "signed",
		PreservationClass: "b_lt",
		RetentionUntil:    retention,
		LegalHold:         true,
		InnerFiles:        []InnerFile{{Name: "content.txt", MediaType: "text/plain", Size: 42}},
		CreatedAt:         created,
		UpdatedAt:         updated,
	}

	if got.ID != want.ID || got.Owner != want.Owner || got.TenantID != want.TenantID ||
		got.Kind != want.Kind || got.ParentID != want.ParentID || got.Filename != want.Filename ||
		got.ContentHash != want.ContentHash || got.Mime != want.Mime || got.Size != want.Size ||
		got.Status != want.Status || got.PreservationClass != want.PreservationClass ||
		!got.RetentionUntil.Equal(want.RetentionUntil) || got.LegalHold != want.LegalHold ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("FromStore mismatch:\ngot  %+v\nwant %+v", got, want)
	}
	if len(got.InnerFiles) != 1 || got.InnerFiles[0] != want.InnerFiles[0] {
		t.Fatalf("InnerFiles mismatch: got %+v, want %+v", got.InnerFiles, want.InnerFiles)
	}
}

func TestFromStoreNoInnerFiles(t *testing.T) {
	d := &store.Document{ID: "doc-2", Kind: "source"}

	got := FromStore(d)

	if got.InnerFiles != nil {
		t.Fatalf("InnerFiles = %#v, want nil for a plain source", got.InnerFiles)
	}
}
