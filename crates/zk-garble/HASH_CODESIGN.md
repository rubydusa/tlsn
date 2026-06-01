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

## Candidates (binary-field, cheap to prove in Binius64)

1. **Vision Mark-32** — Irreducible + 3MI Labs, "ZK-Friendly Hash over Binary
   Tower Fields" (eprint 2024/633). Arithmetization-oriented, *designed* to be
   cheap in Binius. `binius-hash` already ships the Vision permutation
   (`vision_4`, `vision_6`) as a native impl. **Primary candidate.** Its S-box is
   a power map / inversion over GF(2³²) — so the **same hint trick we just used
   for AES transfers** (supply the inverse, verify with one field mul), keeping
   the in-circuit cost low. Caveat: Vision Mark-32 is analyzed as a *sponge hash*,
   not as a TCCR dual-key cipher; using its permutation in an MMO/TMMO-style TCCR
   mode needs a security argument (milestone 2).
2. **Poseidon2b** — binary-field Poseidon/Poseidon2 (eprint 2025/1893). Alternate
   AO permutation over binary fields if Vision's TCCR mode is awkward.
3. **Low-multiplicative-complexity ciphers (LowMC, eprint 2016/687)** — a 3-bit
   quadratic S-box minimizes AND count, so cheap to *garble* and to *prove*.
   But LowMC has substantial cryptanalysis (algebraic / low-data attacks) — only
   with conservative parameters, and probably not worth the risk vs Vision.

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

1. **In-circuit cost of the candidate.** Get a `binius_frontend` gadget for the
   Vision permutation (binius-hash has the native impl; check `binius-circuits`
   for a frontend gadget, else build one — S-box = inversion ⇒ hint-friendly).
   Measure AND-constraints for one TCCR-equivalent evaluation and compare to
   **54,096** (AES). Decision gate: target ≥10× cheaper.
2. **TCCR mode + security.** Define the permutation→TCCR construction (MMO/TMMO),
   state the CCR assumption, and check Vision Mark-32's analysis covers — or can
   be extended to — this mode. This is the gating *research* question.
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
