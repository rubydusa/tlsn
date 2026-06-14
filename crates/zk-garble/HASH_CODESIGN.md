# Step 2 — co-designing a SNARK-friendly garbling hash

> Planning doc. The goal is to replace fixed-key AES as mpz's garbling hash with
> a primitive that is cheap to *prove* in Binius64, collapsing the proof-of-
> garbling cost. Enabled because we fork mpz.

## Why

Post-hint baseline (DESIGN.md §7): one `tccr` = **54,096** binius64
AND-constraints ⇒ ~216k per garbled AND gate ⇒ ~1.4×10⁹ for a single AES block's
garbling — still beyond Binius's practical range (~2²⁸). Micro-optimizing
AES-in-SNARK further (a dedicated `xtime`, cheaper affine) buys maybe ~1.5× more
and then stops. The cost is *fundamentally* "prove a fixed-key AES per gate". The
only order-of-magnitude lever is to stop using AES as the garbling hash.

## Milestone 1 result (measured, `src/bf.rs`)

binius64's word frontend has no native GF(2ᵏ) multiply, so I measured what one
costs when built from word ops:

| variable field-mul              | AND-constraints |
|---------------------------------|-----------------|
| GF(2⁸)  (AES's field)           | 41              |
| GF(2³²) (Vision Mark-32)        | 164             |
| GF(2⁶⁴) (= one binius64 word)   | 262             |

(vs **~1** for a *native* field-mul constraint in the original Binius.) A Vision
permutation's MDS and squarings are GF(2)-*linear* (mult-by-constant / Frobenius)
and cheap; its real cost is the S-box **inversions** — one variable field-mul each
(via hint) × *hundreds* of S-boxes ≈ ~10⁵ AND-constraints. That is **comparable to
a few× worse than the 54,096-AND AES `tccr` — and certainly not the ≥10× *better*
we need.** (An earlier draft said "~17× worse"; that wrongly modeled the MDS as
variable muls — corrected.) **Decision gate: FAIL for binius64.**

Root cause — and the subtle part: "SNARK over binary tower fields" describes where
the *commitment/prover* lives, not the *constraint system*. binius64's constraint
system (`binius-core` `constraint_system.rs`) has exactly two types: `AndConstraint`
(bitwise `A&B=C`, free XOR/shift combos) and `MulConstraint` (64-bit **integer**
mul). There is **no GF(2ᵏ) field-multiply constraint** — so a carryless field mul
must be synthesized from ~one AND per bit (cost grows with field size: 41→164→262).
Vision is cheap in the *original* Binius (AIR over native GF(2ᵏ), field-mul ≈ 1
constraint); binius64 traded that for a CPU-friendly word machine where the cost
unit is the bitwise AND. AES is already competitive *because* it uses the tiny
GF(2⁸); larger-field algebraic hashes cost more per mul here, the opposite of their
advantage under native-field arithmetization. The right metric is **AND-gate
count**, which redirects the candidate list below.

## The binding constraint: what we may swap

Half-gates + free-XOR security rests on the garbling hash being a **circular
correlation-robust** function (CCR / CCRH) — formalized by Bellare–Hoang–Kohno–
Rosulek, "Efficient Garbling from a Fixed-Key Blockcipher" (BHKR13, eprint
2013/426). mpz's `tccr` is the *tweakable* CCR (TCCR) instantiation
(eprint 2019/074 §7.4); free-XOR additionally needs the *circular* variant.

So: **any function with a TCCR/CCR argument is a valid drop-in — and only such a
function is.** We keep the half-gate equations and the free-XOR Δ structure
(DESIGN.md §2) unchanged; only the hash `H` changes. The candidate must come with
(or admit) a CCR security argument in the mode we use it — this is the real
research risk, not the engineering.

## Candidates — redirected by the measurement

The word machine charges ~1 constraint per bitwise AND, so proving "I computed
hash `H`" costs ≈ `H`'s **AND-gate count**. Minimize that.

1. **Low-AND-count primitives (LowMC, eprint 2016/687; Rasta/Dasta family).**
   Built for minimal multiplicative (AND) complexity — hundreds of AND gates — so
   cheap to *prove* in binius64 *and* cheap to *garble* (small garbled circuit):
   a double win, since both costs scale with AND count. **New primary direction.**
   Risk: LowMC has real cryptanalysis (algebraic / low-data attacks) — use
   conservative parameters, or a purpose-built low-AND correlation-robust hash.
2. **Bitsliced AES, not arithmetic AES (a free baseline win).** Our current gadget
   builds the S-box from GF(2⁸) inversion (~27k AND per AES). The *Boolean /
   bitsliced* AES-128 — literally the circuit that gets garbled, S-box ≈ 32 AND
   (Boyar–Peralta) — is ~6.4k AND gates ⇒ ~6.4k AND-constraints, ~4× cheaper than
   our arithmetic gadget and aligned with the garbled circuit. Worth doing
   regardless of the primitive choice.
3. **Vision / Poseidon2b — only if switching proof systems.** Algebraic
   binary-field hashes (eprint 2024/633, 2025/1893) are cheap in the *original*
   Binius (native GF(2ᵏ)), not the binius64 word machine. Strategic fork: stay on
   binius64 (fast CPU) with a low-AND hash, **or** move to Binius (AIR, native
   GF(2ᵏ)) where Vision Mark-32 is ~1 constraint/mul. This is a proof-system
   decision, not a hash decision.

## Milestone result: LowMC measured (`src/lowmc.rs`)

Built candidate 1 — a fixed-key LowMC permutation (Picnic-L1: `n=128`, `m=10`
S-boxes/round, `r=20`; multiplicative complexity `3·m·r = 600`) — as a binius64
gadget, bit-exact against a clean-room reference, and measured its `tccr` (two
permutations, the analog of `aes::tccr`) against the 54,096-AND fixed-key-AES
baseline. **Verdict: PASS — LowMC clears the ≥10× gate, the opposite of Vision.**

| garbling hash                          | one `tccr`, AND-constraints | vs AES `tccr` |
|----------------------------------------|-----------------------------|---------------|
| fixed-key AES (baseline, DESIGN.md §7) | 54,096                      | 1×            |
| LowMC, compilable (`commit_every=2`)   | 5,241                       | **10.3×**     |
| LowMC, S-box floor (`3·m·r` only)      | ~1,200                      | **~45×**      |

Downstream: a garbled AND gate hashes 4×, so per-gate proof cost falls from
≈216k to ≈21k AND-constraints, and one AES-128 block's garbling (~6.4k AND gates)
needs ≈1.3×10⁸ ≈ 2²⁷ constraints — *inside* Binius's ~2²⁸ practical range, where
AES-as-hash sat at ≈1.4×10⁹ ≈ 2³⁰·⁴ (5× over). **LowMC turns proving a single
block's garbling from infeasible into feasible** (≈2²⁵ at the floor).

Two honest qualifiers on the number:

1. **The 10.3× is frontend-limited, not fundamental.** LowMC's only *hard* ANDs
   are the S-box products: 600/permutation (the `3·m·r` floor, ~45×). The rest is
   materializing the dense GF(2)-linear layers — *free* in binius64's constraint
   system (an AND operand may be any XOR-combination of wires), but the
   gate-fusion inliner flattens the composed 20-round linear map without sharing:
   exponential (≈156 s to compile at `r=4`, OOM at `r=20`). We bound it by
   `force_commit`-ing the 128 state bits every `commit_every` rounds (~`N` ANDs
   each), which moves the cost 7.6× (every round) → 10.3× (every other) and would
   approach the 45× floor with a smarter commit policy, structured/sparser linear
   layers, or a frontend that keeps linear maps factored. The S-box count already
   proves the order-of-magnitude headroom.
2. **Cost is matrix-independent; security is now the gate.** The clean-room
   pseudo-random matrices give the same AND-count as the spec's Grain-LFSR ones,
   so the open question is purely cryptographic: LowMC's low multiplicative
   complexity is exactly what its dedicated cryptanalysis targets (algebraic /
   interpolation / difference-enumeration — Dinur et al. 2021; use conservative
   rounds), and half-gates needs a *circular correlation-robust* hash, which a PRP
   claim does not give. A CCR/TCCR mode for a low-AND permutation is milestone 2,
   and now the critical path.

Op-cost model behind these numbers (`op_cost_probes`): in binius64 each `band` is
1 AND constraint — constants are **not** folded, so `band(x, const)` still costs 1
— while `bxor`/`shl`/`sar` fuse into the consuming gate for ~0. So proof cost ≈
AND-gate count, as the redirect predicted; but "linear is free" holds only where
the inliner can absorb it, which deep dense linear layers defeat.

## The tradeoff to quantify

Fixed-key AES is ~1 ns/call via AES-NI, so mpz garbles fast *natively*; algebraic
hashes (Vision etc.) have no hardware path and are much slower to compute
natively but orders of magnitude cheaper to *prove*. Garbling is offline
(preprocess) and the proof is the bottleneck, so trading native speed for proof
cost is the right direction — but measure both. A 100× proof win at a 10× native
garbling slowdown is a clear win; confirm the actual ratio.

## Online evaluation cost measured (`crates/lowmc-eval-bench`)

The proof-cost win above is offline; so is garbling. The one LowMC cost that runs
*live during the TLS session* — and is therefore bounded by the server's read
timeout — is **evaluation**: the circuit evaluator computes 2 `tccr` = **4 LowMC
permutations per garbled AND gate** as it streams the session. Swapping AES-NI (a
few ns/call in hardware) for LowMC (no hardware path) is a real online slowdown, so
the question is not "is it cheaper" but "does it still fit the timeout". Measured in
`crates/lowmc-eval-bench` (bitsliced LowMC-128/128/20, frequency-invariant
cycles/block via `perf`, i7-1165G7):

| evaluation kernel                          | cyc / perm | 4 KB session (≈10.4M perms)        |
|--------------------------------------------|------------|-------------------------------------|
| AES-NI `tccr` (for reference)              | ~6         | ~17 ms                              |
| LowMC bitsliced — compact gather (`v1`)    | ~1,200     | ~3.4 s                              |
| LowMC bitsliced — **AVX-512 (`tight_b`)**  | **~730**   | **~1.9 s @ 4 GHz / ~2.7 s @ 2.8 GHz** |

(4 KB session ≈ 2.6M AND gates ⇒ ×4 perms/gate ≈ 10.4M evaluation-permutations;
the gate count is an estimate.) **Verdict: LowMC evaluation stays ~120× AES in
cycles but lands at ~2 s/session — inside typical TLS read timeouts, with margin.**
LowMC's proof-cost win therefore does *not* buy an un-evaluable online circuit.

Engineering notes (the bench documents the path):

- **Explicit AVX-512 + unchecked CSR gather is the win** (~730 cyc, instructions
  halved vs the autovectorized baseline) — the autovectorizer leaves the `zmm`
  XOR-accumulate on the table, so it must be written by hand.
- **Fully unrolling the fixed matrices into straight-line code ("matrix codegen")
  is a 13× *regression*** (~9,900 cyc/perm, IPC 0.45). Bitslicing already amortizes
  the per-set-bit bookkeeping across 512 blocks, so the per-block budget is tiny and
  the megabytes of unrolled code starve the instruction front-end. The compact loop
  hot in L1I is *why* the kernel is fast — do not unroll it.
- Multiple accumulators lift IPC but trade it back in instructions: the kernel
  plateaus at ~730, load/throughput bound, ~2.3× above the ~320 cyc/perm floor (the
  residual gap is gather indirection, hard to close without the cache-blowing unroll).

Caveat: this is the *fixed-key permutation* eval cost. The eventual TCCR mode
(milestone 2) wraps the permutation (MMO/TMMO ≈ 1–2 perms + a few XORs), so the
per-`tccr` online cost tracks this number; re-measure once the mode is fixed.

## Integration in the forked mpz

- The hash is called in `mpz/crates/garble-core/src/garbler.rs::and_gate` (and
  the evaluator) via `mpz_core::aes::FixedKeyAes::tccr`.
- Introduce a `trait GarbleHash { fn tccr(&self, tweak, x) -> Block; ... }` with
  two impls: fixed-key AES (today) and the new candidate, selected by config.
  The garbler and evaluator must agree on the hash.
- The proof-of-garbling circuit (DESIGN.md §4) then models the *new* hash instead
  of AES — that is where the win lands.

## Milestones

1. ✅ **Done — Vision FAILS, LowMC PASSES.** Vision: GF(2³²) mul = 164 AND ⇒ a
   permutation ≈ 10⁵–10⁶ AND (`src/bf.rs`). LowMC: one `tccr` = **5,241 AND ⇒
   10.3×** vs AES's 54,096, S-box floor ~45× (`src/lowmc.rs`; see "Milestone
   result: LowMC measured"). **Next:** milestone 2 — a CCR/TCCR argument and mode
   for a low-AND permutation (the gating *research* question) — alongside closing
   the frontend gap toward the 45× floor (commit policy / structured linear
   layers). Cheap interim win still on the table: the bitsliced-AES gadget (~6.4k
   AND).
2. **TCCR mode + security.** Define the permutation→TCCR construction (MMO/TMMO)
   and the CCR argument for the chosen primitive — the gating *research* question.
   With LowMC measured, this is the critical path, not the proof-cost.
3. **mpz integration.** Add the `GarbleHash` trait + candidate impl in garble-core
   behind a config; keep `test_mpc` green with the new hash end-to-end.
4. **End-to-end measurement.** Native garbling time + proof size/time for a small
   `C`, vs the AES baseline. (Online *evaluation* cost — the timeout-bound one — is
   already measured: `crates/lowmc-eval-bench`, ~730 cyc/perm ⇒ ~2 s per 4 KB
   session; see "Online evaluation cost measured".)
5. **Proof circuit.** Re-target `build_proof_of_garbling` at the new hash; per-gate
   cost should now make a full-session proof tractable.

## Recent adjacent work to read first

- **Mosaic**, "Practical Malicious Security for Garbled Circuits on Bitcoin"
  (eprint 2026/812) — directly in our space (malicious GC + public ledger).
- **Argo**, "MAC Garbling with Elliptic Curve MACs" (eprint 2026/049); **Glock /
  Shrinking Glock** (Alpen Labs) — garbled circuits anchored to Bitcoin.
- "Efficient Arithmetic in Garbled Circuits" (eprint 2024/139) and the CCRH
  arithmetic-garbling line (Argo/BABE) — relevant if arithmetic garbling is ever
  reconsidered; all rest on the same CCRH primitive we are swapping.
- **BHKR13** (eprint 2013/426) — the CCR model any replacement hash must satisfy.
