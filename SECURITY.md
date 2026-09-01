# Security policy

This service is the one place document bytes live. It owns ingest, the canonical digest every
signature is ultimately made over, envelope-encrypted storage with a per-object key, the access
rules that decide who may read a document back, container assembly, and the retention sweep that
destroys it all again. It does not sign, does not call the signer, and does not produce a
validation verdict.

Two failures matter most, and they pull in opposite directions: **bytes reaching someone who should
not have them**, and **the digest not being the bytes**. The first is a data breach. The second is a
signature over something the signer never saw.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/signbyte/document-store/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings — several behaviours
  differ between the production backends and the development ones;
- whether you have told anyone else, and whether a disclosure date already binds you.

**Please do not send us real documents, tokens, keys or personal data.** A synthetic file and a
redacted trace explain almost any finding here.

## What we consider most serious

**A document reaching the wrong reader.** Every content read is authenticated, scope-checked and
authorised against an access list, bound to the token subject or an invited identity, and enforced
in the database. Serious findings: any path to bytes or metadata that skips that check; an
authorisation decision made only in the service and not in the data layer; and anything that lets a
caller *distinguish* a document that does not exist from one they may not see — absence and
no-access are deliberately indistinguishable, because the difference is itself a disclosure.

**A guard enforced in one layer and not the other.** Domain rules live in the service code **and**
in the stored procedures, and both are load-bearing. A rule tightened in only one of them is a real
finding even when the request still ends up refused today, because the two drift apart silently and
the next change lands on the weaker one.

**The digest not matching the bytes.** It is computed once at ingest and handed out forever after;
everything downstream signs it without re-deriving it. Anything that lets the stored digest and the
stored bytes disagree — a swap after ingest, a digest copied between objects, a recomputation on a
different byte range — produces a signature over content the signer never saw.

**Container assembly failing open.** Assembly self-checks the digest references — count, filename
and hash — before storing. A mismatch must be rejected, not stored with a warning.

**A download that can execute.** A document is any file a person wants signed, so raw-byte
downloads force an attachment disposition, disable content-type sniffing, and coerce
browser-active types to a neutral one. A path that returns stored bytes with an active content
type, an inline disposition, or without the sniffing guard is stored cross-site scripting on the
portal's own origin — and it needs no privilege beyond uploading a file.

**Bytes or keys where they must never be.** In the database; in a log line, trace, metric or error
message; in a domain event or audit record; in the clear at rest; or a plaintext data key that
persists rather than living only for the operation.

**Retention that does not destroy.** An object, its data key, or its metadata surviving the sweep
past its window; a hold applied or honoured where it should not be; history erasure skipped. This
service is minimised by default on purpose, and a sweep that quietly keeps things is a privacy
failure even though nothing looks broken.

**A chain with more than one live head**, or a head that is not the latest — the one-live-document
rule is what makes a co-signer sign the right thing.

**A development concession reachable in production** — the in-memory metadata or blob store, the
ephemeral KMS key. Each warns loudly at start-up; a configuration in which one is selected silently,
or in which the warning is absent, is a finding.

Denial of service is worth reporting here rather than being dismissed: whole artifacts are buffered
in memory, so the file-size cap is also the per-request memory bound, and a path that reads an
artifact without honouring it is a real problem. Findings that need an already-compromised host or
an already-authenticated administrator remain lower priority. Reports about outdated dependencies
are welcome where you can show the vulnerable path is actually reachable.

## What is deliberately not a finding

- **Signature detection is structural, never cryptographic.** On upload this service reports that a
  signature *exists*; it never claims it is valid. Validity is the orchestrator's verdict.
- **This service runs no signature validation and holds no signing key.** It self-checks digest
  references on assembly, which is an integrity check, not a trust decision.
- **An unreachable malware scanner fails open with a warning, by design**, and the scan is skipped
  entirely when no scanner is configured. That is documented behaviour, not a defect. A scanner
  result of *found* being ignored, or a path that skips a configured and reachable scanner, **is** a
  finding.

A report that an API *implies* one of the guarantees above, or that a caller is likely to read it
that way, is a real finding.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## Scope

This policy covers the code in this repository. It does not cover the object store, the key
management service, the database, the malware scanner, the orchestrating services, or any
deployment operated by someone other than us — report those to the parties that run them. How a
deployment configures this service is the operator's responsibility, but a report that a **default**
is unsafe is very much in scope.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
