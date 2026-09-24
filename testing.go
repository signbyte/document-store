package documentstore

import (
	"testing"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
)

// TestApp builds an App for tests: in-memory metadata + blob stores, an ephemeral
// dev KMS key, no signer / GDPR-audit / broker wiring, and a stub auth middleware
// driven by the X-Test-Scopes request header (production always uses the
// go-authbyte DPoP middleware).
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "document-store")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("SERVICE_AUDIENCE", "svc:document")
	// One client is allowed to own documents, so the product-owned path is
	// reachable in tests exactly as a deployment configures it.
	tb.Setenv("DOCUMENT_PRODUCT_CLIENTS", "svc:test-product-client=testproduct")

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	app.SetAuthMiddleware(TestAuthMiddleware())

	return app
}

// TestAuthMiddleware authenticates requests from the X-Test-Scopes header
// (comma-separated scopes, e.g. "documents:read,documents:write") and uses the
// optional X-Test-Sub header as the caller identity / document owner (default
// "svc:test-client"). Requests without scopes are rejected 401 — mirroring the
// production contract.
func TestAuthMiddleware() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			scopes := ctx.Header.Get("X-Test-Scopes")
			if scopes == "" {
				ctx.StatusCode(401)
				ctx.Text("unauthorized")

				return
			}

			sub := ctx.Header.Get("X-Test-Sub")
			if sub == "" {
				sub = "svc:test-client"
			}

			claims := map[string]token.ClaimStrings{
				"sub":   {sub},
				"scope": {scopes},
			}
			// Optional eIDAS serial — the ACL matches an invited co-signer on it.
			if serial := ctx.Header.Get("X-Test-Serial"); serial != "" {
				claims["serial_number"] = token.ClaimStrings{serial}
			}
			// Optional organisation — a service account that is also a member of
			// one carries it, and a product-owned document is scoped by it.
			if tenant := ctx.Header.Get("X-Test-Tenant"); tenant != "" {
				claims["tenant"] = token.ClaimStrings{tenant}
			}
			ctx.SetUser(user.New(claims))
			next(ctx)
		}
	}
}
