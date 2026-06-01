# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

TLSNotary: a Rust implementation of a protocol for proving facts about TLS sessions (data provenance) without revealing the full transcript, using secure multi-party computation (MPC). Security-critical cryptographic software, under active development with expected breaking changes.

## Commands

The repo pins Rust **1.96.0** (see `.github/workflows/ci.yml`). `rustfmt` and the WASM build additionally require **nightly**.

```sh
./pre-commit-check.sh        # Runs the full CI approximation: fmt, clippy, build, unit + integration tests
```

Individual steps (each is a separate CI job):

```sh
cargo +nightly fmt --check --all                                   # Format check — MUST use nightly (imports_granularity)
cargo clippy --all-features --all-targets --locked -- -D warnings  # Lint; warnings are errors in CI
cargo build --all-targets --locked
cargo test --locked                                                # Unit tests + non-ignored tests
```

**Integration tests are gated behind `#[ignore]`** and only run under the `tests-integration` profile with `--include-ignored`. Three crates are excluded because they are upstream forks / have no meaningful integration tests:

```sh
cargo test --locked --profile tests-integration --workspace \
  --exclude tlsn-tls-client --exclude tlsn-tls-core --exclude tlsn-sdk-core \
  -- --include-ignored
```

Running a single test:

```sh
cargo test -p tlsn-core merkle                       # unit test by substring in one crate
cargo test -p tlsn --test test test_mpc -- --ignored # one ignored integration test (test_mpc / test_proxy live in crates/tlsn/tests/test.rs)
```

`crates/examples-zk` is **intentionally excluded from the workspace** (it pulls ~1 GB of `noir-lang/noir` git deps). Build it from its own directory: `cd crates/examples-zk && cargo build --release --locked`.

Set the version across all manifests with the cargo-script: `./set_tlsn_version.rs <version>` (e.g. `0.1.0-alpha.16`).

### WASM

Requires nightly + `wasm32-unknown-unknown` + `rust-src` (pinned in `crates/wasm/rust-toolchain`), `wasm-pack` 0.14.0+ (`cargo install wasm-pack`), and **clang 16+** (older clang fails with "No available targets are compatible with triple wasm32-unknown-unknown" — common on macOS; `brew install llvm` and prepend it to `PATH`).

```sh
cd crates/wasm && ./build.sh   # Output package in crates/wasm/pkg
```

### Harness (browser + network-realistic integration/benchmarks)

The `crates/harness` tree is a **standalone test/bench harness**, separate from `cargo test`. It runs the protocol across real network namespaces (native) or a headless browser (WASM), with configurable bandwidth/latency. This is the only way to exercise the browser prover and realistic network conditions.

```sh
cd crates/harness
./build.sh                          # Builds runner + native/wasm executors into ./bin/
sudo ./bin/runner setup             # Creates a virtual network (requires root)
./bin/runner test                   # Native tests; add --target browser for the browser executor
./bin/runner test --list
./bin/runner bench -c bench.toml -o metrics.csv
sudo ./bin/runner clean             # Tears down the network
```

Add native/browser test cases as plugins in `crates/harness/executor/test_plugins/` (registered via the `test!` macro); add/modify benchmarks in `crates/harness/bench*.toml`. Browser mode hanging is usually a host firewall dropping bridge traffic — see `crates/harness/README.md`.

## Architecture

The protocol has **three roles** and **two phases**, with two interchangeable commitment backends.

**Roles** — `Prover` connects to the real TLS server; `Verifier` collaborates over MPC without learning plaintext; **Notary** is a `Verifier` that additionally signs an attestation (`Role` enum in `crates/tlsn/src/lib.rs` classifies a Notary as a Verifier).

**Phases** — (1) *Commitment*: prover and verifier jointly run the TLS session so the verifier obtains an authenticated commitment to the transcript without seeing it. (2) *Selective Disclosure*: the prover reveals chosen ranges and proves statements about them.

**Two commitment backends**, selected via `ProtocolConfig` (`crates/tlsn/src/lib.rs`) — both drive the same `crates/tlsn` prover/verifier:
- **MPC** (`MpcTlsConfig` → `Mpc`): full 2PC TLS; the verifier never sees the keys. The heavyweight, trust-minimized path. Integration test `test_mpc`.
- **Proxy** (`ProxyTlsConfig` → `Proxy`, `crates/tlsn/src/proxy.rs`): lighter path. Integration test `test_proxy`.

### Crate layering

```
examples / wasm / harness         ← entry points & bindings
        │
   sdk-core (crates/sdk-core)      ← high-level SDK over tlsn + attestation; IO-trait abstraction, WASM feature
        │
   tlsn (crates/tlsn)              ← protocol orchestration: Session, Prover, Verifier; selects Mpc vs Proxy
        ├── attestation (crates/attestation)  ← post-commitment doc/proof model (see below)
        ├── core (crates/core)                ← Transcript, commitments, merkle, connection info, configs, fixtures
        ├── formats (crates/formats)          ← HTTP/JSON transcript parsing for structured commitments
        └── mpc-tls (crates/mpc-tls)          ← MPC TLS handshake + record layer; Leader (prover) / Follower (verifier)
                └── components/                ← MPC primitives composed by mpc-tls:
                        cipher, hmac-sha256 (PRF/key derivation),
                        key-exchange (3-party ECDH), deap
                            │
                          mpz  ← THE MPC engine (external git dep, see below)
```

`crates/tls/{core,client}` are **forks of `rustls`** adapted so TLS crypto can run inside MPC; they are excluded from `rustfmt` (`rustfmt.toml`) and from integration-test runs. `crates/server-fixture/*`, `crates/tls/server-fixture`, and `crates/data-fixtures` are test servers/data.

### The mpz dependency

The actual MPC machinery — garbled circuits, oblivious transfer, the secure VM, memory, share conversion, ZK — lives in the **external `mpz` library** (`privacy-ethereum/mpz`), pinned by git rev in `Cargo.toml` (currently `v0.1.0-alpha.6`). `mpc-tls` and the `components/*` crates allocate values in an `mpz` VM and execute AES-GCM / HMAC-SHA256 / ECDH circuits over it. Bumping the `mpz` (or `tlsn-utils`: `mux`, `spansy`, etc.) rev is a coordinated, cross-cutting change, not a routine dependency bump.

### Attestation model (`crates/attestation`)

`Request` (what the prover wants attested) → `Attestation` (a Merkle-rooted document signed by the Notary; prover keeps the `Secrets` alongside) → `Presentation` (built from attestation + secrets, reveals selected transcript ranges) → `Presentation::verify(...)` lets an external party check it offline against the trusted Notary key. Verification must work on minimal targets: `tlsn-core` and `tlsn-attestation` are CI-checked to compile and verify with `RUSTFLAGS='--cfg getrandom_backend="unsupported"'` (test `no_syscall_verify`).

## Conventions & gotchas

- **`Cargo.lock` is checked in** for reproducible builds and must be updated whenever `Cargo.toml` changes. The team typically commits lockfile updates separately. CI runs everything `--locked`.
- **WASM compatibility is a hard constraint** for most crates: use `web-time` instead of `std::time`, no syscalls on the verification path, JS `getrandom` backend in the browser.
- **Comment style is CI-adjacent and enforced in review**: line and doc comments are capitalized and end with a period; function docs start with a third-person present-tense verb ("Creates", "Computes"); document parameters under a `# Arguments` section; soft 100-char comment-line limit.
- This is cryptographic code: handle secret data carefully (zeroize, never log), use only cryptographic RNG, and avoid panics on the protocol path that could leak state. Protocol/commitment changes warrant extra scrutiny (see `.github/prompts/review.md`).
