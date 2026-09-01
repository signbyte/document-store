# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. This service is the only place document bytes live, so a change that fights its
design is better redirected before it is written than after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). Every dependency is public, so
nothing needs credentials, a `GOPRIVATE` setting or a vendor directory. The gate a change must pass
is the same one CI runs:

```sh
go build ./...
go vet -tags integration ./...
go test -race -count=1 ./...
```

Note the build tag on `vet`. A test behind the `integration` tag needs a live database and object
store, so **it is deliberately not run** in CI — but `vet` and the linter compile it, so it cannot
silently rot. If you change anything it touches, compile it the same way before you push.

Three more checks run in CI and are worth running first:

- **Lint** — `golangci-lint run --build-tags integration`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **The image** — CI builds it, generates an SBOM, fails on HIGH/CRITICAL findings from a
  vulnerability scan, and signs it. A change to the [Dockerfile](Dockerfile) should be built
  locally first, because that job is slow to fail.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

The unit tests need no database, object store, key service or scanner: each has an in-memory or
fake backend. Those same development backends exist in the running service and warn loudly at
start-up — keep it that way; a concession that stops being loud is how it reaches production.

## What a change to this service needs

Read the **Security invariants** section of the [README](README.md) first. Each one is the reason a
specific class of defect cannot happen, and a change that weakens one is the change, not a side
effect.

The four that carry the most weight:

- **A domain rule lives in two layers, and both must move together.** Guards are enforced in the
  service code **and** in the stored procedure. Changing only one leaves the other as the real
  behaviour — usually the service pre-check, which refuses the request before the corrected
  procedure is ever reached, so the fix looks like it did nothing. Grep the rule across the service
  layer, the in-memory test double, and the procedure; change all of them, or none.
- **The digest is computed once and never re-derived.** Anything that lets the stored digest and the
  stored bytes disagree produces a signature over content nobody saw. Assembly's reference
  self-check — count, filename, hash — rejects rather than stores on a mismatch, and stays that way.
- **Downloads must never be able to execute.** Raw-byte responses force an attachment disposition,
  disable sniffing, and coerce browser-active content types. The stored bytes are untouched; only
  the outbound headers change. A new byte-returning endpoint inherits all of it — this is the one
  rule most easily lost by adding a route.
- **Absence and no-access are indistinguishable.** Authorisation failures and missing documents
  answer alike, deliberately. A more helpful error here is an enumeration oracle.

Also load-bearing:

- **No byte in the database, no plaintext data key at rest, no content in a log, trace, metric,
  error, event or audit record.** Audit records carry a digest and metadata.
- **Tables are never touched directly.** All state goes through the security-definer procedures
  under an execute-only role. A change needing a new column or query is a change to the procedures.
- **Minimised by default.** Everything carries a retention window and is destroyed by the sweep —
  bytes *and* data key. Durable retention is opt-in, never a side effect.
- **Whole artifacts are buffered in memory**, so the file-size cap is also the per-request memory
  bound. A new path that reads an artifact honours the cap before reading, not after.
- **A new configuration knob needs a safe default and a row in the README's Configuration table.**
  A knob whose unsafe setting is the default, or that only appears in the code, is a finding waiting
  to be filed.

## Proposing a change

- Work on a branch and open a pull request against `develop`. `develop` is merged into `main` and
  tagged there when a release goes out, so `main` is never committed to directly.
- **Sign off every commit.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): by adding a
  `Signed-off-by: Your Name <you@example.org>` line you certify that you wrote the change or
  otherwise have the right to submit it under this project's licence. `git commit -s` adds the line
  for you; the name and address must match the commit author. A pull request whose commits lack it
  fails the DCO check and cannot be merged.
- Keep the change focused: one concern per pull request.
- A change in behaviour comes with a test that fails without it.
- Match the style around you — naming, error handling, comment density. Comments explain what and
  why in plain domain terms; a reference to a standard is cited in the bracket form already used in
  the code.
- A change an operator or an integrator can feel — a new or changed endpoint, field, error code,
  configuration knob or default — belongs in [CHANGELOG.md](CHANGELOG.md) in the same pull request.
- Pull requests also run a dependency review. A new dependency needs a reason the standard library
  or the existing ones cannot cover.

## Licence

This project is licensed under the **GNU Affero General Public License, version 3 only** (see
[LICENSE](LICENSE)). By submitting a contribution you agree that it is provided under the same
licence.

Worth knowing what AGPL means here, because this is a service rather than a library: if you run a
modified version and let others interact with it over a network, the licence requires you to offer
those users the corresponding source of your modified version. Using it unmodified, or modifying it
for purely internal use with no network users, does not trigger that.
