//! Experimental: publicly verifiable **proof of garbling** as an alternative to
//! DEAP's dual-execution check.
//!
//! The idea: instead of catching a malicious garbler interactively (DEAP runs
//! the circuit a second time in a ZK VM and equality-checks the outputs), the
//! garbler proves *once*, in a preprocessing phase, that the garbled circuit it
//! published is a correct half-gate garbling of the agreed circuit `C`, and
//! that the input-wire labels offered via OT are the same labels used in `C`.
//! The proof is a Binius64 SNARK — transparent, public-coin (Fiat-Shamir), and
//! **publicly verifiable**, so it can be posted to a ledger and checked by any
//! third party (not just the evaluator). This deliberately avoids interactive /
//! designated-verifier ZK.
//!
//! See `DESIGN.md` in this crate for the full protocol, threat model, the
//! proof-circuit specification, and the open problems (prover cost, on-chain
//! verification of FRI-style proofs).
//!
//! This crate is scaffolding: the function below is a stub that wires the two
//! libraries (Binius64 frontend + the mpz garbling core) together so the
//! integration compiles; the constraint system itself is TODO.
#![allow(unused)]

pub mod aes;
pub mod bf;

use binius_frontend::{Circuit as ProofCircuit, CircuitBuilder, Wire};
use mpz_circuits::Circuit as GarbledFn;
use mpz_garble_core::{Delta, Key};

/// Builds the Binius64 constraint system that proves a half-gate garbling of
/// `garbled_fn` was constructed correctly.
///
/// STUB. Per `DESIGN.md` §"Proof circuit", the witness is `Delta` and the input
/// 0-labels; the public inputs are a commitment to the published encrypted
/// gates and to the OT-offered label pairs; and the constraints recompute, for
/// every AND gate, the two half-gate ciphertexts (XOR + fixed-key-AES / TCCR)
/// and assert they match the published gate — all native binary-field ops in
/// Binius64 (`bxor`, `band`).
pub fn build_proof_of_garbling(garbled_fn: &GarbledFn) -> ProofCircuit {
    let builder = CircuitBuilder::new();
    let _ = garbled_fn.and_count(); // AND gates drive the constraint count.

    // TODO(§Proof circuit): allocate Delta + input-label witnesses, the
    // encrypted-gate public inputs, and emit the per-gate garbling constraints.

    builder.build()
}
