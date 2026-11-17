# ADR 0003: A sealed JSON baseline, with an optional HMAC key

- **Status:** Accepted (M1)

## Context

A file integrity monitor is only as trustworthy as its baseline. An attacker who can change a
watched file can often change the baseline too, and a baseline that silently accepts edits turns
the monitor into a tool that vouches for the attacker. A plain checksum detects accidental
corruption but not a deliberate edit, because the attacker can recompute it. A keyed MAC
detects deliberate edits as long as the key is not available to the attacker.

## Decision

The baseline is one JSON file holding the policy, every entry and a `seal` over its canonical
form (sorted keys, no whitespace):

- `sha256:<hex>` by default, which detects corruption and careless edits;
- `hmac-sha256:<hex>` when `--key-file` is given (at least 16 bytes), which detects deliberate
  edits by anyone without the key.

Loading checks the seal before using any field. A keyed baseline without a key is refused, and a
plain-digest baseline is refused when a key is given, so an attacker cannot replace a keyed
baseline with an edited one that carries a recomputed plain digest. The policy is stored inside
the baseline, so `scan` and `watch` always use the policy the baseline was made with.

## Consequences

- The file is easy to review, diff and copy off the host; verification needs only Python's
  standard library (`hmac`, `hashlib`, `json`).
- The HMAC protects against an attacker without the key. If the key sits on the same host as a
  root attacker, it does not; the README and RFC say so, and keeping the key off the host (or
  verifying from another machine) is the recommended setup.
- JSON is slower than a database for very large trees; M1 targets thousands of files. A format
  change would bump `version`, which loaders already check.
