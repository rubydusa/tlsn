# lowmc-eval-bench

Microbenchmark for the **online evaluation cost** of a LowMC-as-garbling-hash
circuit — the cost that runs live during the TLS session and is bounded by the
server's read timeout. (Garbling and proving are offline; only evaluation is on
the clock.) Companion to the proof-cost work in
[`../zk-garble/HASH_CODESIGN.md`](../zk-garble/HASH_CODESIGN.md).

It evaluates a clean-room bitsliced **LowMC-128/128/20** permutation — the hash
`H`; a garbled AND gate costs 2 `tccr` = **4 permutations** to evaluate — across a
512-block AVX-512 batch, and reports **frequency-invariant cycles/block** (the dev
laptop throttles, so ns is unreliable; cycles/block is throttle-proof, read via
`perf-event`). The matrices are clean-room SplitMix64 (~50% dense, representative);
cost is matrix-independent, so this measures the engineering, not a specific
instance.

## Requirements

- **Linux** (`perf-event` is Linux-only — this is why the crate is excluded from
  the workspace).
- **AVX-512** CPU (`tight_b/c/d` use `_mm512_*`); built with `-C target-cpu=native`
  via the local `.cargo/config.toml`.
- `perf_event_paranoid <= 2` to read CPU counters unprivileged:
  `sudo sysctl kernel.perf_event_paranoid=2`. Without it the bench falls back to
  (throttling-sensitive) nanoseconds.

## Run

```sh
cd crates/lowmc-eval-bench
cargo run --release
# pin to one core for stable counts:
taskset -c 0 ./target/release/lowmc-eval-bench
```

## What it shows (i7-1165G7, frequency-invariant)

| backend          | cyc/block | ins/block | IPC | note                                   |
|------------------|-----------|-----------|-----|----------------------------------------|
| `v1` gather      | ~1.1–1.3k | 3011      | 2.3 | baseline (bounds-checked autovec)      |
| `tight_a` autovec| ~2.3k     | 3539      | 1.5 | **worse** — autovectorizer mangles it  |
| **`tight_b`** avx512 | **~730** | **1327** | 1.8 | **winner — instructions halved, 1.6×** |
| `tight_c` 4-acc  | ~735      | 1552      | 2.1 | higher IPC, more instructions — plateau|
| `tight_d` 8-acc  | ~745      | 1406      | 1.9 | plateau                                |

At ~730 cyc/perm a 4 KB TLS session (~2.6M AND gates ⇒ 10.4M eval-perms) evaluates
in **~1.9 s @ 4 GHz / ~2.7 s @ 2.8 GHz** — inside typical TLS read timeouts.
AES-NI eval is ~6 cyc/perm (~17 ms/session); LowMC stays ~120× in cycles but fits.

The `tight_b` win comes from **explicit AVX-512 + unchecked CSR gather**, not from
unrolling: the fully-unrolled "matrix codegen" approach is a 13× regression
(front-end starvation, IPC 0.45) and is documented — but not shipped — in
`HASH_CODESIGN.md`. Multiple accumulators (`tight_c/d`) lift IPC but trade it back
in instructions, so cycles plateau: the kernel is load/throughput bound at ~730,
~2.3× above the ~320 cyc/block theoretical floor, the gap being gather indirection.
