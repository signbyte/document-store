package store

import "testing"

// Bundleable: an unsigned source or an already-signed file (PDF or ASiC-E container)
// can be absorbed into a bundle — a signed input rides in as a data object with its
// own signatures intact. An unsigned container is a draft bundle (rebundled, never an
// input), and other kind/status combinations are excluded.
func TestBundleable(t *testing.T) {
	cases := []struct {
		kind, status string
		want         bool
	}{
		{"source", "received", true},     // an unsigned upload
		{"pdf", "signed", true},          // an already-signed PDF
		{"container", "signed", true},    // a signed .asice — an annex rides in as a data object
		{"container", "received", false}, // an unsigned .asice is a draft bundle — rebundle it
		{"source", "signed", false},      // a source is never "signed"
		{"pdf", "received", false},       // an unsigned PDF is stored kind=source, not pdf
	}
	for _, c := range cases {
		if got := Bundleable(c.kind, c.status); got != c.want {
			t.Errorf("Bundleable(%q, %q) = %v, want %v", c.kind, c.status, got, c.want)
		}
	}
}
