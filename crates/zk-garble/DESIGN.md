# Publicly verifiable proof-of-garbling (DEAP alternative)

> Status: research scaffolding. This documents the intended protocol; the crate
> currently only wires Binius64 + the mpz garbling core together.

## 1. Goal

Replace DEAP's interactive dual-execution check with a **non-interactive,
publicly verifiable SNARK proof that the garbler constructed the garbled circuit
correctly** and that the input labels delivered by OT correspond to that circuit.
Because the proof is public-coin and transparent (Binius64, Fiat-Shamir), the
proof + commitments can be posted to a public ledger and checked by anyone — not
only the evaluator. We explicitly avoid interactive / designated-verifier ZK
(IZK), since those are not publicly auditable.

## 2. What we are replacing

In MPC mode the **prover is the garbler**, the **verifier is the evaluator**
(`crates/tlsn/src/deps/{prover,verifier}.rs`). Garbling is mpz's semi-honest
half-gates ([ZRE15]), `mpz/crates/garble-core`:

- Free-XOR: one global `Delta`; the 1-label of a wire is `w_0 ⊕ Δ`. XOR/INV/ID
  gates are free; only AND gates cost two ciphertexts.
- A garbled AND gate (`garble-core/src/garbler.rs::and_gate`) publishes
  `(t_g, t_e)` where, with `H` = tweakable circular-correlation-robust hash
  (fixed-key AES, tweak = gate id):
  ```
  t_g = H(x0) ⊕ H(x1) ⊕ (lsb(y0)·Δ)          x1 = x0 ⊕ Δ,  y1 = y0 ⊕ Δ
  w_g = H(x0) ⊕ (lsb(x0)·t_g)
  t_e = H(y0) ⊕ H(y1) ⊕ x0
  w_e = H(y0) ⊕ (lsb(y0)·(t_e ⊕ x0))
  z0  = w_g ⊕ w_e            (output 0-label)
  ```
- The evaluator obtains the active labels for **its own** input wires via
  correlated OT (`DerandCOT` over KOS→Ferret), where the COT correlation is the
  same `Δ`.

A malicious garbler can garble a *wrong* function or offer OT labels that differ
from the circuit's (selective-failure). DEAP catches this by re-running in a ZK
VM and equality-checking; the SNARK below catches it by *proving* the garbling.

## 3. The alternative flow: garble-and-prove

**Phase A — agree on `C` (public).** Both parties fix the boolean circuit `C`
(the TLS computation: AES-CTR/GCM, GHASH, SHA-256 PRF, …) as an
`mpz_circuits::Circuit`. `C` is public.

**Phase B — garbler preprocess (offline).** The garbler:
1. Samples `Δ` and input 0-labels; garbles `C` → encrypted gates `GC`.
2. Publishes/commits `GC` (a hash/Merkle root `cm_GC` for the ledger).
3. Commits to the OT-offered input-label pairs `cm_OT = Com({(K_i, K_i⊕Δ)})`.
4. Produces a **Binius64 proof `π`** for the statement in §4.

This lands naturally in the existing `preprocess()` phase — proving is offline
and off the critical TLS path.

**Phase C — transfer + OT.** Evaluator receives `GC`; runs OT for its input
wires (labels bound by `cm_OT`).

**Phase D — verify (public).** Anyone checks `π` against public `(C, cm_GC,
cm_OT)`. Valid ⇒ `GC` is a correct garbling of `C` and the OT labels match it.
`(C, cm_GC, cm_OT, π)` is the publicly auditable artifact for the ledger.

**Phase E — online.** Evaluator evaluates `GC` as usual; no DEAP second
execution. Soundness toward the verifier/public comes from `π`.

## 4. The proof circuit (what Binius64 proves)

Statement (ZK in `Δ` and the labels; public `C`, `cm_GC`, `cm_OT`):

> ∃ `Δ`, input 0-labels `{K_i}` s.t. running the half-gate garbling of the
> public `C` under `(Δ, {K_i})` yields exactly the committed `GC`, and the
> committed OT pairs equal `{(K_i, K_i⊕Δ)}`.

The verifier circuit re-derives the garbling:
- Wire 0-labels propagate through XOR/INV/ID **linearly** (GF(2)-affine in
  `{K_i}` and `Δ`) — cheap, native `bxor` in Binius64.
- For each **AND** gate, recompute `H(x0), H(x1), H(y0), H(y1)` (four fixed-key
  AES evaluations with the gate-id tweak) and assert `t_g`, `t_e` equal the
  committed gate via the equations in §2; derive `z0` for downstream wires.
- Open `cm_GC`, `cm_OT` (Merkle / hash gadget) and bind the labels.

So the proof is essentially "garble `C` again, inside the SNARK, and check it
matches." Dominant cost = (cost of one fixed-key-AES in-circuit) × (4 ·
`C.and_count()`). This is **why Binius64**: garbling is XOR- and AES-heavy, and
binary-field SNARKs encode XOR/AND/AES far more cheaply than prime-field SNARKs
that must emulate GF(2). Binius64's frontend has native `bxor`/`band` and a
64-bit-word constraint model (`binius_frontend::CircuitBuilder`).

## 5. OT ↔ circuit correspondence (selective failure)

The classic attack: the garbler uses `(w0, w1)` in `GC` but offers `(w0, ŵ1)`,
`ŵ1 ≠ w1`, in the OT, learning the evaluator's bit from whether it aborts.
Folding `cm_OT` into the SNARK (Phase B.3 / §4) **subsumes committed-OT**: the
proof binds the OT-offered pairs to the exact `GC` input labels, so a verified
`π` guarantees consistency. Alternatively use a verifiable/committed OT whose
sender commitment is the public input to the proof.

## 6. Security model — scope and non-goals

- **Covers:** correctness of the garbler's circuit construction + OT-label
  consistency, made *publicly* verifiable. Upgrades the garbler side from
  semi-honest to malicious-with-public-auditability, replacing DEAP's role here.
- **Does NOT, by itself, cover:**
  - The **key exchange / PMS**: that is a separate share-conversion 2PC
    (`crates/components/key-exchange`), with its own in-circuit consistency
    check. It must be handled separately (or also proven).
  - **Evaluator-side** misbehavior and input consistency on that side.
  - **Privacy:** `π` MUST be zero-knowledge in `Δ` and the 0-labels — revealing
    them breaks label secrecy. Binius64 supports ZK (`zk_config` in
    prover/verifier); confirm it is enabled for the proving path.

## 7. Costs and open problems (read before committing)

1. **Prover cost.** Proving a whole TLS-session garbling ≈ re-garbling it in
   the SNARK: ~`4·and_count` AES evaluations. AES-128 ≈ 6k AND gates/block, and
   a transcript is many blocks → large. It is offline (preprocess), but
   estimate constraint counts early on a small `C` before scaling.
2. **On-chain verification.** Binius/FRI-Brakedown proofs are **large
   (tens–hundreds of KB) and hash-heavy to verify** — *publicly verifiable* but
   NOT cheap to verify directly in a smart contract. For a ledger, plan for
   either (a) post `π` as data availability + verify off-chain, or (b) recursively
   wrap `π` into a small on-chain-friendly proof (proof composition — on the
   Binius64 roadmap). Distinguish "publicly verifiable" from "cheap on-chain".
3. **Proof size vs Groth16.** No trusted setup and post-quantum, at the price of
   larger proofs than pairing-based SNARKs. Acceptable for DA; not for tiny
   calldata.
4. **TCCR-AES in-circuit.** The fixed-key-AES hash must be modeled exactly as
   mpz uses it (`mpz_core::aes` TCCR, tweak = gate id). Any mismatch breaks
   soundness silently. Pin and test against `garble-core` vectors.

## 8. Prior work (summary)

- **Garble-then-Prove** (Xie et al., USENIX Sec'24, eprint 2023/964) — the
  closest predecessor: garble semi-honestly, then a cheap *prove* phase upgrades
  to malicious security for TLS attestation. But it uses **designated-verifier**
  ZK (evaluator = verifier). Our contribution = make the prove phase **publicly
  verifiable** via a transparent SNARK.
- **Publicly Auditable Garbled Circuit** (eprint 2025/772, 2025) — most recent
  work directly on publicly auditable GC evaluation.
- **Verifiable garbling** (Bellare–Hoang–Rogaway, CCS'12) — defines the
  verifiability/authenticity properties this proof realizes.
- **JKO13** (Jawurek–Kerschbaum–Orlandi, CCS'13) — GC-to-ZK; privacy-free
  garbling + open-and-check, the template for "prove the garbling".
- **Publicly Verifiable Covert (PVC)** — Asharov–Orlandi (AC'12); Hong–Katz–
  Kolesnikov–Lu–Wang (EC'19); Faust et al. "Financially Backed Covert Security"
  (PKC'22): publicly verifiable *certificates of cheating* judged by a smart
  contract (constant-size, ~354 B). Weaker guarantee (deter, not prevent) but
  the established "evidence-to-ledger" model.
- **Authenticated garbling** (Wang–Ranellucci–Katz, CCS'17) — the efficient
  *interactive* malicious 2PC baseline DEAP-family protocols relate to.
- **Binius / Binius64** (Diamond–Posen, eprint 2023/1784; Irreducible 2025) —
  transparent, post-quantum SNARKs over binary tower fields; native XOR/AND/shift
  on 64-bit words; the tooling that makes proving garbling tractable.

## 9. Milestones

1. Model one fixed-key-AES (TCCR) call in `binius_frontend`; test vs
   `mpz_core::aes`.
2. Prove one garbled AND gate (the §2 equations); test vs `garble-core::and_gate`.
3. Propagate labels through a whole `mpz_circuits::Circuit`; prove a small `C`
   (e.g. one AES block); measure constraints/proof size/prover time.
4. Add `cm_GC` / `cm_OT` commitment gadgets and the OT binding (§5).
5. Integrate as a `TlsCommitConfig` variant parallel to `Mpc`/`Proxy`, swapping
   the DEAP path for garble-and-prove on the garbler side.
