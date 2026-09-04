# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

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
