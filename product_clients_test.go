package documentstore

import "testing"

// Which clients may own documents is configuration, and the parsing of it decides
// whether a deployment's intent actually reaches the service. An entry that does
// not parse must leave the client owning nothing rather than owning something
// slightly wrong — the owner is what makes a document releasable later.
func TestProductForReadsTheConfiguredClients(t *testing.T) {
	for _, tc := range []struct {
		name, configured, client, want string
	}{
		{"a single entry", "svc:a-documents=alpha", "svc:a-documents", "alpha"},
		{
			"one of several, with the spacing people actually type",
			" svc:a-documents=alpha , svc:b-documents = beta ",
			"svc:b-documents", "beta",
		},
		{"a client that is not listed", "svc:a-documents=alpha", "svc:b-documents", ""},
		{"nothing configured", "", "svc:a-documents", ""},
		{"an entry with no product", "svc:a-documents", "svc:a-documents", ""},
		{"no client on the request", "svc:a-documents=alpha", "", ""},
		{
			// A near-miss must not match: ownership is compared whole.
			"a client whose name merely starts the same way",
			"svc:a-documents=alpha", "svc:a-documents-2", "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Configuration{DocumentProductClients: tc.configured}
			if got := c.ProductFor(tc.client); got != tc.want {
				t.Fatalf("ProductFor(%q) with %q = %q, want %q",
					tc.client, tc.configured, got, tc.want)
			}
		})
	}
}
