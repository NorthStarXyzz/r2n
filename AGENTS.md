# R2N Agent Guide

R2N is a pure Rust virtual LAN project for building encrypted room-based connectivity across the public Internet. The system is centered on low-latency UDP peer-to-peer paths, NAT traversal, LAN-style discovery forwarding, and supernode relay fallback.

This file defines the working rules for any coding agent operating in this repository.

## Project Goals

- Build a general-purpose virtual LAN, not a game-specific tunnel
- Prefer direct UDP peer-to-peer paths whenever possible
- Keep relay support through `r2n-supernode` as a fallback path
- Preserve LAN semantics such as broadcast, multicast, mDNS, SSDP, and related discovery traffic
- Maintain a pure Rust core with clear workspace boundaries

## Architecture Overview

- `apps/supernode`: binary entrypoint for the supernode service
- `apps/cli`: binary entrypoint for the local CLI and daemon runner
- `crates/r2n-edge-lib`: edge runtime, IPC handling, room activation, peer state, and supernode coordination
- `crates/r2n-supernode-lib`: room lifecycle, rendezvous, invite creation, and relay forwarding
- `crates/r2n-dataplane`: packet forwarding, flood control, peer path handling, and virtual LAN traffic logic
- `crates/r2n-tun`: cross-platform TUN/TAP backend
- `crates/r2n-nat`: NAT probing, inference, and port mapping
- `crates/r2n-discovery`: discovery packet classification and policy
- `crates/r2n-policy`: traffic restriction rules
- `crates/r2n-config`: unified edge and supernode configuration

## Core Engineering Rules

- Use Rust for all core networking, transport, crypto, routing, and dataplane logic
- Prefer `tokio` for asynchronous control-plane workflows
- Keep crate responsibilities narrow and explicit
- Reuse existing crate boundaries before introducing new crates or abstractions
- Prefer low-allocation and in-place packet handling on hot paths
- Do not log sensitive keys, tokens, invite secrets, or plaintext payload data
- Keep code comments in English
- Keep repository-authored documentation in English unless a file is explicitly intended to be localized

## Git Rule

Every modification to this repository must be followed by a Git commit.

This rule is mandatory.

- If you change code, commit it
- If you change documentation, commit it
- If you change scripts, configuration, assets, or tests, commit it
- Do not leave completed repository changes uncommitted at the end of a task
- Prefer clear commit messages that describe the intent of the change

## Build and Validation

Before finishing a task, run the most relevant checks for the affected scope:

- `cargo fmt`
- `cargo check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`

At minimum:

- run `cargo check` for code changes
- run `cargo test` when behavior changes or tests are affected
- run `cargo clippy --all-targets --all-features -- -D warnings` before release-facing changes when practical

## Security Expectations

- Handshake and session establishment must remain aligned with the current Noise-based design
- Dataplane encryption must remain AEAD-protected
- Room isolation is a core contract
- Invite integrity is a core contract
- Supernodes may coordinate and relay, but should not gain access to end-to-end plaintext payloads

## Performance Expectations

- Favor direct UDP paths over relay whenever possible
- Avoid unnecessary allocations in dataplane and relay-critical paths
- Be cautious with clones, heap growth, and hot-path serialization
- Keep platform-specific fast paths aligned with existing implementation strategy

## Documentation Expectations

- Keep `README.md`, `README_CN.md`, `SECURITY.md`, release scripts, and packaging notes consistent with the real repository state
- If a file, script, document, or packaging path is removed, update any references that still point to it
- Do not claim release readiness unless build, packaging, and documentation paths are actually working

## Release Mindset

R2N is still evolving toward a polished public release. Treat release readiness as a full-system concern, not just a successful compile.

A release-facing change should consider:

- build health
- test health
- packaging health
- installation flow
- deployment documentation
- platform validation
- security reporting clarity
