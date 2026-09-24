package routes

import (
	"encoding/json"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

const (
	scopeDurable = "documents:durable"
	// The client this test configuration allows to own documents, and the product
	// it belongs to. A client that is not listed owns nothing, whatever it holds.
	productClient = "svc:test-product-client"
	productOwner  = "product:testproduct:"
	testOrg       = "01K3YB8N7QW4T2MJ6RX5D0C9AF"
	otherOrg      = "01K9ZZ0000000000000000000"
	scopeAll      = scopeRead + "," + scopeWrite + "," + scopeDurable
)

// upload posts one document. Scopes, the calling client and the organisation it
// acts for are all the caller's to vary, because those three are exactly what
// decides whether a durable document may be stored at all.
func upload(t *testing.T, app *azugo.TestApp, scopes, sub, tenant string, fields map[string]string) *fasthttp.Response {
	t.Helper()
	tc := app.TestClient()

	if fields == nil {
		fields = map[string]string{}
	}
	body, ct := buildMultipart(t, fields, []fileEntry{{"file", "attachment.txt", []byte("an attachment")}})

	resp, err := tc.Post("/api/v1/documents", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopes),
		tc.WithHeader("X-Test-Sub", sub),
		tc.WithHeader("X-Test-Tenant", tenant))
	qt.Assert(t, qt.IsNil(err))

	return resp
}

// readDocument fetches one document's metadata as the given caller.
func readDocument(t *testing.T, app *azugo.TestApp, id, sub, tenant string) *fasthttp.Response {
	t.Helper()
	tc := app.TestClient()

	resp, err := tc.Get("/api/v1/documents/"+id,
		tc.WithHeader("X-Test-Scopes", scopeRead),
		tc.WithHeader("X-Test-Sub", sub),
		tc.WithHeader("X-Test-Tenant", tenant))
	qt.Assert(t, qt.IsNil(err))

	return resp
}

// A durable document is stored under the product that stored it, for the
// organisation the token names, and with no date at all — which is what makes it
// a document nothing sweeps.
func TestIngestDurableIsProductOwnedAndUndated(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp := upload(t, app, scopeAll, productClient, testOrg, map[string]string{"retention_class": "durable"})
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var ing response.Ingested
	decode(t, resp, &ing)
	qt.Check(t, qt.Equals(ing.RetentionClass, "durable"))

	got := readDocument(t, app, ing.ID, productClient, testOrg)
	qt.Assert(t, qt.Equals(got.StatusCode(), fasthttp.StatusOK))

	var doc response.Document
	decode(t, got, &doc)

	// The owner names the product and the organisation and NOTHING about the
	// credential that presented the request. That is the whole point: rotating
	// the secret cannot orphan a document nothing else would ever remove.
	qt.Check(t, qt.Equals(doc.Owner, productOwner+testOrg))
	qt.Check(t, qt.Equals(doc.TenantID, testOrg))
	qt.Check(t, qt.Equals(doc.RetentionClass, "durable"))
	qt.Check(t, qt.IsNil(doc.RetentionUntil))

	// And the absence reaches the wire AS an absence, not as a placeholder instant
	// a reader would take for a real deadline.
	var raw map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(bodyOf(t, got), &raw)))
	v, present := raw["retentionUntil"]
	qt.Check(t, qt.IsTrue(present))
	qt.Check(t, qt.IsNil(v))
}

// An ordinary upload is untouched by any of this.
func TestIngestDefaultRemainsServiceDated(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp := upload(t, app, scopeRead+","+scopeWrite, "svc:test-client", "", nil)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var ing response.Ingested
	decode(t, resp, &ing)
	qt.Check(t, qt.Equals(ing.RetentionClass, "ttl"))

	var doc response.Document
	decode(t, readDocument(t, app, ing.ID, "svc:test-client", ""), &doc)
	qt.Check(t, qt.Equals(doc.Owner, "svc:test-client"))
	qt.Check(t, qt.IsNotNil(doc.RetentionUntil))
}

// The three ways a caller can fail to be allowed to create storage no clock
// removes. Each is a 403, and none of them stores anything.
func TestIngestDurableCallerRefusals(t *testing.T) {
	for _, tc := range []struct{ name, scopes, sub, tenant string }{
		{"without the durable scope", scopeRead + "," + scopeWrite, productClient, testOrg},
		{"without an organisation", scopeAll, productClient, ""},
		{"as a client that owns nothing", scopeAll, "svc:not-a-product", testOrg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := testApp(t)
			app.Start(t)
			defer app.Stop()

			resp := upload(t, app, tc.scopes, tc.sub, tc.tenant,
				map[string]string{"retention_class": "durable"})
			qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
		})
	}
}

// The refusals that are about the request rather than the caller.
func TestIngestRetentionRequestRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]string
	}{
		{"an unknown class", map[string]string{"retention_class": "forever"}},
		{
			// The service owns the clock for its own class, so a caller offering a
			// date there is told so rather than having it silently dropped.
			"a date without the durable class",
			map[string]string{"retention_until": time.Now().Add(time.Hour).Format(time.RFC3339)},
		},
		{
			"a date that is not an instant",
			map[string]string{"retention_class": "durable", "retention_until": "next tuesday"},
		},
		{
			// Under a sweep that honours an owner's date, a past one means "remove
			// this at the next opportunity" — almost never what anyone meant.
			"a date already in the past",
			map[string]string{
				"retention_class": "durable",
				"retention_until": time.Now().Add(-time.Hour).Format(time.RFC3339),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := testApp(t)
			app.Start(t)
			defer app.Stop()

			resp := upload(t, app, scopeAll, productClient, testOrg, tc.fields)
			qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
		})
	}
}

// An owner may bound how long it keeps a document — an organisation's own
// data-protection policy is exactly that case — and the date it sets is kept.
func TestIngestDurableKeepsAnOwnerSetDate(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	until := time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)
	resp := upload(t, app, scopeAll, productClient, testOrg, map[string]string{
		"retention_class": "durable",
		"retention_until": until.Format(time.RFC3339),
	})
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var ing response.Ingested
	decode(t, resp, &ing)

	var doc response.Document
	decode(t, readDocument(t, app, ing.ID, productClient, testOrg), &doc)
	qt.Assert(t, qt.IsNotNil(doc.RetentionUntil))
	qt.Check(t, qt.IsTrue(doc.RetentionUntil.Equal(until)))
}

// Another organisation's identity, and a person, are both told the document does
// not exist — in the same words a document that was never stored gets, because
// anything else confirms the id to whoever is asking.
func TestProductOwnedIsInvisibleOutsideItsOrganisation(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp := upload(t, app, scopeAll, productClient, testOrg, map[string]string{"retention_class": "durable"})
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var ing response.Ingested
	decode(t, resp, &ing)

	absent := readDocument(t, app, "01K0000000000000000ABSENT", productClient, testOrg)
	qt.Assert(t, qt.Equals(absent.StatusCode(), fasthttp.StatusNotFound))
	absentBody := refusalShape(t, absent)

	for _, tc := range []struct{ name, sub, tenant string }{
		{"another organisation's product", productClient, otherOrg},
		{"a person", "person-subject", ""},
		{"a client that owns nothing", "svc:not-a-product", testOrg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := readDocument(t, app, ing.ID, tc.sub, tc.tenant)
			qt.Check(t, qt.Equals(got.StatusCode(), fasthttp.StatusNotFound))
			qt.Check(t, qt.Equals(refusalShape(t, got), absentBody))
		})
	}
}

// The owning product's own delete is the release, and the document is gone after
// it. A caller that cannot read it cannot release it either.
func TestProductReleasesItsOwnDocument(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp := upload(t, app, scopeAll, productClient, testOrg, map[string]string{"retention_class": "durable"})
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var ing response.Ingested
	decode(t, resp, &ing)

	del := func(sub, tenant string) int {
		tc := app.TestClient()
		r, err := tc.Delete("/api/v1/documents/"+ing.ID,
			tc.WithHeader("X-Test-Scopes", scopeRead+","+scopeWrite),
			tc.WithHeader("X-Test-Sub", sub),
			tc.WithHeader("X-Test-Tenant", tenant))
		qt.Assert(t, qt.IsNil(err))
		code := r.StatusCode()
		fasthttp.ReleaseResponse(r)

		return code
	}

	qt.Check(t, qt.Equals(del(productClient, otherOrg), fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(del(productClient, testOrg), fasthttp.StatusNoContent))
	qt.Check(t, qt.Equals(
		readDocument(t, app, ing.ID, productClient, testOrg).StatusCode(),
		fasthttp.StatusNotFound))
}

// refusalShape is a refusal body with its correlation id removed. Everything else
// must match a genuinely absent document byte for byte; the trace id is per-request
// by design and is the one field that legitimately differs.
func refusalShape(t *testing.T, resp *fasthttp.Response) string {
	t.Helper()

	var body map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(bodyOf(t, resp), &body)))
	delete(body, "trace_id")
	out, err := json.Marshal(body)
	qt.Assert(t, qt.IsNil(err))

	return string(out)
}
