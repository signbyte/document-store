# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The Document Service as first released: the platform's single source of truth for document
bytes and hashes — ingest, the canonical SHA-256 digest, envelope-encrypted object storage
with per-object KMS-wrapped data keys, retention TTL with a background sweep, ASiC-E container
assembly and completion, and a signed-PDF store guarded by a one-live-document-per-chain rule.
AGPL-3.0-only.
