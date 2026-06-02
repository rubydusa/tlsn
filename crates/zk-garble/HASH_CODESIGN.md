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

## The tradeoff to quantify

Fixed-key AES is ~1 ns/call via AES-NI, so mpz garbles fast *natively*; algebraic
hashes (Vision etc.) have no hardware path and are much slower to compute
natively but orders of magnitude cheaper to *prove*. Garbling is offline
(preprocess) and the proof is the bottleneck, so trading native speed for proof
cost is the right direction — but measure both. A 100× proof win at a 10× native
garbling slowdown is a clear win; confirm the actual ratio.

## Integration in the forked mpz

- The hash is called in `mpz/crates/garble-core/src/garbler.rs::and_gate` (and
  the evaluator) via `mpz_core::aes::FixedKeyAes::tccr`.
- Introduce a `trait GarbleHash { fn tccr(&self, tweak, x) -> Block; ... }` with
  two impls: fixed-key AES (today) and the new candidate, selected by config.
  The garbler and evaluator must agree on the hash.
- The proof-of-garbling circuit (DESIGN.md §4) then models the *new* hash instead
  of AES — that is where the win lands.

## Milestones

1. ✅ **Done — Vision FAILS the gate (`src/bf.rs`).** GF(2³²) mul = 164 AND ⇒ a
   Vision permutation ≈ 10⁵–10⁶ AND (3–17× worse than AES); see "Milestone 1
   result". **Next:** pick a low-AND CR hash for binius64 (LowMC-family or
   purpose-built) and measure one evaluation vs 54,096 — *or* take the
   proof-system fork (original Binius for Vision). Cheap interim win: build the
   bitsliced-AES gadget (~6.4k AND) to replace the arithmetic one.
2. **TCCR mode + security.** Define the permutation→TCCR construction (MMO/TMMO)
   and the CCR argument for the chosen primitive — the gating *research* question.
3. **mpz integration.** Add the `GarbleHash` trait + candidate impl in garble-core
   behind a config; keep `test_mpc` green with the new hash end-to-end.
4. **End-to-end measurement.** Native garbling time + proof size/time for a small
   `C`, vs the AES baseline.
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
