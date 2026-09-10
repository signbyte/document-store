# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.2

### Changed — a chain grant is stored in one canonical spelling of the identity code

`POST /api/v1/documents/{id}/acl` now rewrites the `serial` it is given to one spelling before
storing it: the identity type, the country, a hyphen, and the national code with its separators
removed. A co-signer's own identity code is reduced the same way before it is matched. So a grant
written `PNOLV-010180-15097` is matched by a co-signer whose token carries `PNOLV-01018015097`, and
the other way round — which they previously were not.

```http
POST /api/v1/documents/{id}/acl
Content-Type: application/json

{ "serial": "PNOLV-010180-15097", "rights": ["read", "cosign"] }
```

The entry is stored against `PNOLV-01018015097`. The country stays part of the key, so the same
eleven digits in another country belong to another person and match nothing.

**A `serial` that names no country is now refused** — `422 err:document:invalidSerial`, repeating no
identity code back. The workflow service that calls this route has already resolved a country from
the person it invited, so a bare code arriving here means that resolution did not happen: it is a
fault to name, not a nationality to invent.

### Changed — the metrics endpoint no longer offers OpenMetrics

A scraper that asked for the OpenMetrics format by sending `Accept: application/openmetrics-text`
used to be answered in it, with the `# EOF` terminator that format requires. This service now
answers in the Prometheus text format whatever the scraper asks for, and writes no `# EOF`:

```http
GET /metrics
Accept: application/openmetrics-text

200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

**The metric names, labels and values are unchanged**, so Prometheus — and anything else that
accepts the plain-text exposition format — needs nothing done. Two setups need a look: a scrape
configuration that *requires* the OpenMetrics content type, and a check that reads a missing
`# EOF` as a truncated scrape. Both need their expectation relaxed.

The endpoint itself is unchanged otherwise: still `/metrics` (or `METRICS_PATH`), still enabled by
default, and still answered only for trusted addresses (`METRICS_TRUSTED_IPS`, `127.0.0.1` by
default) — so if nothing scrapes this service, there is nothing to do. The change arrives from the
web framework this service is built on rather than from a change of its own, carried in with the
shared libraries below.

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

## v0.1.1

### Fixed — an archive timestamp added by a co-signer is recorded, and answers 200

`POST /api/v1/documents/{id}/archived` now records the document's upgrade to long-term
preservation (`preservationClass = "preservation"`) in the same database write as the replaced
bytes. Before, the fact was written in a second step that only the uploader could pass: any other
party on the document's access list — a co-signer adding an archive timestamp to the document they signed — had the bytes
replaced and then received `404 err:document:notFound`, so the screen asked them to try again and
every retry stamped the container once more, while the row never showed the document as preserved.
Now every party the access list lets read the document gets the same answer, and a refused fact
leaves the bytes untouched. The response shape is unchanged.

**Deployment note:** the change rides on the platform database — `document.replace_container_blob`
accepts the class and `document.set_preservation_class` is dropped. Apply that migration before or
together with this version: an older service against the new database fails its archive-timestamp route
loudly (the dropped procedure), while this version against an older database swaps the bytes without
recording the fact.

## v0.1.0

Initial code.

The Document Service as first released: the platform's single source of truth for document
bytes and hashes — ingest, the canonical SHA-256 digest, envelope-encrypted object storage
with per-object KMS-wrapped data keys, retention TTL with a background sweep, ASiC-E container
assembly and completion, and a signed-PDF store guarded by a one-live-document-per-chain rule.
AGPL-3.0-only.
