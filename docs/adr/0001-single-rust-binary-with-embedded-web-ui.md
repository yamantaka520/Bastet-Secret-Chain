# ADR 0001 — A single Rust binary with an embedded Web UI

- **Status:** accepted, 2026-09-03
- **Deciders:** project owner

## Context

The vault must serve two very different consumers: a human using a browser, and
AI agents making HTTP calls while a task runs. It must also install easily on
macOS, Windows, and Linux and start at boot without a logged-in desktop session.

A desktop-window application (Tauri/Electron) suits the human but is a poor fit
for a background service that agents call. A pure CLI suits the agent but not
the classification and upload workflow. Two separate programs would double the
install story and split the audit path.

## Decision

Ship one Rust binary, `bsc`, that is CLI, daemon, and web server, with the React
single-page app compiled into the binary. SQLite in WAL mode is the store.

## Consequences

- One artifact per platform; installation is a copy plus `bsc service install`.
- The UI is always version-matched to the daemon that serves it.
- Matches the Bastet Workstation stack (Rust + React + SQLite WAL), so review
  knowledge and patterns transfer between the projects.
- The UI cannot be updated independently of the daemon. Accepted.
- No native OS window; the operator opens a browser. A tray helper may be added
  later, but it is not on the critical path.
