# ADR 0002 — A reference URL is not a credential

- **Status:** accepted, 2026-09-03
- **Deciders:** project owner
- **Supersedes:** nothing. This is the project's defining constraint.

## Context

The product requirement is a copy button that yields a URL an agent can call to
obtain a secret. The obvious implementation — a URL whose possession returns the
secret — makes that URL a bearer credential.

URLs are the least private thing in a system. They land in shell history,
process argument lists visible to every local user, web server and proxy logs,
browser history, bug reports, and — critically for this product — the context
window and transcript of the very AI agent that used them, which is often
persisted and sometimes uploaded.

## Decision

The copied URL is an **opaque reference to an item**, never authority over it.
Retrieval requires a separately-issued, scoped bearer token presented in the
`Authorization` header. The reference id is random and unguessable, but its
secrecy is not a security control.

A single exception is provided for the copy-into-a-chat workflow: an explicit,
off-by-default **handoff link** that carries a single-use token in the URL. It
is bound to loopback, expires in 60 seconds, is invalidated on first use, is
labeled in the UI as a live credential, and emits its own audit action.

## Consequences

- A leaked reference URL discloses only that an item exists.
- Agents need configuration (a token), not just a paste. This is friction, and
  it is the point; the token minting flow is designed to make it a few seconds.
- The UI must state this plainly at the moment of copying, otherwise the
  operator will assume the URL is the secret and treat it too casually — or too
  carelessly.
- Any future feature that would make a URL alone sufficient must supersede this
  ADR explicitly, in writing.
