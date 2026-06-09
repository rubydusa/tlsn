//! LowMC permutation gadget for Binius64 — the step-2 candidate hash
//! (HASH_CODESIGN.md, "Candidates", item 1).
//!
//! LowMC (Albrecht–Rechberger–Schneider–Tiessen–Zohner, eprint 2016/687) is a
//! block cipher built for *minimal multiplicative complexity*: a partial S-box
//! layer (`m` parallel 3-bit S-boxes, 3 ANDs each) wrapped in dense
//! GF(2)-linear layers. Its whole AND budget is `3·m·r`, and binius64 charges
//! ~1 AND constraint per bitwise `band` while folding XOR/shift into the
//! consuming gate for free — so a LowMC evaluation should prove in ≈ `3·m·r`
//! AND constraints, against the 54,096 of one fixed-key-AES `tccr` (DESIGN.md
//! §7).
//!
//! # Representation
//!
//! Each of the `N` state bits is held in its own wire as a **full-word mask**
//! (all-ones = 1, all-zeros = 0). Then `band(maskₐ, mask_b)` is the bit-AND and
//! `bxor` is the bit-XOR, both correct across all 64 lanes. The dense linear
//! layers become `bxor_multi` of selected masks — linear, hence ~free after
//! gate fusion — so the only hard AND constraints are the S-box `band`s. No bit
//! is ever packed or shifted, so no shift materializes as an AND.
//!
//! # Caveat (this is a cost/equivalence probe, not a production cipher)
//!
//! The round matrices and constants here are clean-room pseudo-random
//! (SplitMix64), not the spec's Grain-LFSR output, and are not invertibility-
//! checked. Neither fact changes the AND-constraint count or the gadget-vs-
//! reference equivalence this milestone measures; a real instance swaps in the
//! spec matrices. Using LowMC *as a correlation-robust garbling hash* further
//! needs a CCR argument and a permutation→TCCR mode — the open research step
//! (HASH_CODESIGN.md milestone 2), not addressed here.

use binius_frontend::{CircuitBuilder, Wire};
use std::array;

// ───────────────────────────── Parameters (Picnic-L1) ────────────────────────
//
// Block/key size 128, `m` = 10 S-boxes/round, `r` = 20 rounds — the LowMC
// instance used by the Picnic L1 signature, multiplicative complexity 3·m·r =
// 600. (Picnic L3 = 192/10/30, L5 = 256/10/38.)

/// State and key size in bits.
const N: usize = 128;
/// S-boxes per round (the partial S-box layer touches the low `3·M` bits).
const M: usize = 10;
/// Number of rounds.
const R: usize = 20;

/// Fixed public key folded into the round keys, making the keyed cipher a fixed
/// public permutation `π` — the analog of `mpz_core::aes::FIXED_KEY`.
const FIXED_KEY: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;

// ───────────────────────────── Public matrices/constants ─────────────────────

/// The public, fixed LowMC round data for [`FIXED_KEY`].
struct Params {
    /// Linear layer matrices `L[0..R]`; each is `N` rows, a row stored as a
    /// column-bitmask over the state.
    l: Vec<[u128; N]>,
    /// Round constants `C[0..R]`.
    c: Vec<u128>,
    /// Round keys `rk[0..=R]` (`rk[i] = K[i]·FIXED_KEY`), already specialized
    /// to the fixed key, so the key schedule contributes no constraints.
    rk: Vec<u128>,
}

/// SplitMix64 step — a deterministic public PRG for the clean-room matrices.
fn splitmix64(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Draws a pseudo-random `N`-bit row/constant.
fn rand_bits(s: &mut u64) -> u128 {
    ((splitmix64(s) as u128) << 64) | (splitmix64(s) as u128)
}

/// GF(2) matrix–vector product: `out` bit `row` is the parity of `rows[row] &
/// x`.
fn matvec(rows: &[u128; N], x: u128) -> u128 {
    let mut out = 0u128;
    for (row, mask) in rows.iter().enumerate() {
        let parity = ((mask & x).count_ones() & 1) as u128;
        out |= parity << row;
    }
    out
}

/// Generates the fixed public round data (deterministic; identical for the
/// gadget and the reference).
fn params() -> Params {
    let mut s = 0x5AFE_C0DE_1234_5678u64;
    // Order matters only for reproducibility: keys, then linear layers, then
    // constants. Both the gadget and the reference read this same stream.
    let key_mats: Vec<[u128; N]> = (0..=R)
        .map(|_| array::from_fn(|_| rand_bits(&mut s)))
        .collect();
    let l: Vec<[u128; N]> = (0..R)
        .map(|_| array::from_fn(|_| rand_bits(&mut s)))
        .collect();
    let c: Vec<u128> = (0..R).map(|_| rand_bits(&mut s)).collect();
    let rk: Vec<u128> = key_mats.iter().map(|k| matvec(k, FIXED_KEY)).collect();
    Params { l, c, rk }
}

// ───────────────────────────── In-circuit gadget ─────────────────────────────

/// XORs the public constant `cst` into the mask-per-bit `state` (bit `j` is
/// flipped iff `cst` bit `j` is set). Linear — folds into the consuming gate.
fn add_constant(b: &CircuitBuilder, state: &mut [Wire; N], cst: u128, all_ones: Wire) {
    for (j, bit) in state.iter_mut().enumerate() {
        if (cst >> j) & 1 == 1 {
            *bit = b.bxor(*bit, all_ones);
        }
    }
}

/// Applies the linear layer `rows` to `state`: output bit `row` is the XOR of
/// the state masks selected by `rows[row]`. All `bxor` — no AND constraints.
fn linear_layer(b: &CircuitBuilder, rows: &[u128; N], state: &[Wire; N], zero: Wire) -> [Wire; N] {
    array::from_fn(|row| {
        let terms: Vec<Wire> = (0..N)
            .filter(|&col| (rows[row] >> col) & 1 == 1)
            .map(|col| state[col])
            .collect();
        match terms.len() {
            0 => zero,
            1 => terms[0],
            _ => b.bxor_multi(&terms),
        }
    })
}

/// Applies the partial S-box layer in place: the LowMC 3-bit S-box on each of
/// the low `M` triples, identity elsewhere. The triple for S-box `j` is
/// `(c, b, a) = (state[3j], state[3j+1], state[3j+2])` with `a` the high bit,
/// and
///
/// ```text
/// a' = a ⊕ (b·c),  b' = a ⊕ b ⊕ (a·c),  c' = a ⊕ b ⊕ c ⊕ (a·b).
/// ```
///
/// The three products are the only `band`s — 3 AND constraints per S-box.
fn sbox_layer(b: &CircuitBuilder, state: &mut [Wire; N]) {
    for j in 0..M {
        let (c, bb, a) = (state[3 * j], state[3 * j + 1], state[3 * j + 2]);
        let bc = b.band(bb, c);
        let ac = b.band(a, c);
        let ab = b.band(a, bb);
        state[3 * j + 2] = b.bxor(a, bc);
        state[3 * j + 1] = b.bxor_multi(&[a, bb, ac]);
        state[3 * j] = b.bxor_multi(&[a, bb, c, ab]);
    }
}

/// Fixed-key LowMC permutation `π` over the mask-per-bit state.
///
/// # Arguments
/// * `input` - the 128 state-bit masks (all-ones / all-zeros per bit).
/// * `commit_every` - rounds between forced state commitments. LowMC's linear
///   layers are dense and the rounds are deep, so leaving them as symbolic XOR
///   combinations makes binius64's gate-fusion inliner flatten the composed
///   linear maps without sharing — exponential time (≈156 s at r=4 with no
///   commits, OOM at r=20). Committing the 128 state bits every `commit_every`
///   rounds caps the inline depth, making compilation tractable. Cost: each
///   committed bit is one materialized AND constraint, so the dense linear
///   layers cost ~`N` AND-constraints per committed round, even though they are
///   GF(2)-linear "for free" in principle. Smaller = faster compile, more ANDs;
///   larger = fewer ANDs toward the `3·m·r` S-box floor, slower compile. `0`
///   never force-commits (exponential — avoid for `r` beyond a handful).
pub fn lowmc_permutation(b: &CircuitBuilder, input: [Wire; N], commit_every: usize) -> [Wire; N] {
    let p = params();
    let all_ones = b.add_constant_64(u64::MAX);
    let zero = b.add_constant_64(0);

    let mut state = input;
    add_constant(b, &mut state, p.rk[0], all_ones); // Initial whitening.
    for i in 0..R {
        sbox_layer(b, &mut state);
        state = linear_layer(b, &p.l[i], &state, zero);
        add_constant(b, &mut state, p.c[i] ^ p.rk[i + 1], all_ones);
        if commit_every != 0 && (i + 1) % commit_every == 0 {
            for &bit in &state {
                b.force_commit(bit);
            }
        }
    }
    state
}

/// The garbling hash `tccr(t, x) = π(π(x) ⊕ t) ⊕ π(x)` instantiated with the
/// LowMC permutation — the apples-to-apples analog of [`crate::aes::tccr`], so
/// its AND-constraint count is directly comparable to AES's 54,096. See
/// [`lowmc_permutation`] for `commit_every`.
pub fn lowmc_tccr(
    b: &CircuitBuilder,
    tweak: [Wire; N],
    x: [Wire; N],
    commit_every: usize,
) -> [Wire; N] {
    let px = lowmc_permutation(b, x, commit_every);
    let p_xor_t: [Wire; N] = array::from_fn(|i| b.bxor(px[i], tweak[i]));
    let ppt = lowmc_permutation(b, p_xor_t, commit_every);
    array::from_fn(|i| b.bxor(ppt[i], px[i]))
}

// ───────────────────────────── Reference oracle ──────────────────────────────

/// The LowMC 3-bit S-box on `(a, b, c)` with `a` the high bit (test oracle).
fn sbox3_ref(a: u128, bb: u128, c: u128) -> (u128, u128, u128) {
    (a ^ (bb & c), a ^ bb ^ (a & c), a ^ bb ^ c ^ (a & bb))
}

/// Reference partial S-box layer: the low `M` triples, identity elsewhere.
fn sbox_layer_ref(mut s: u128) -> u128 {
    for j in 0..M {
        let c = (s >> (3 * j)) & 1;
        let bb = (s >> (3 * j + 1)) & 1;
        let a = (s >> (3 * j + 2)) & 1;
        let (na, nb, nc) = sbox3_ref(a, bb, c);
        s &= !(7u128 << (3 * j));
        s |= (nc << (3 * j)) | (nb << (3 * j + 1)) | (na << (3 * j + 2));
    }
    s
}

/// Reference fixed-key LowMC permutation, used as ground truth for the gadget.
fn lowmc_perm_ref(input: u128) -> u128 {
    let p = params();
    let mut s = input ^ p.rk[0];
    for i in 0..R {
        s = sbox_layer_ref(s);
        s = matvec(&p.l[i], s);
        s ^= p.c[i] ^ p.rk[i + 1];
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::{verify::verify_constraints, word::Word};
    use binius_frontend::CircuitStat;

    /// Spreads a 128-bit value into 128 full-word masks (all-ones / all-zeros).
    fn mask(bit_src: u128, j: usize) -> Word {
        Word(if (bit_src >> j) & 1 == 1 { u64::MAX } else { 0 })
    }

    #[test]
    fn sbox_is_a_bijection() {
        // The LowMC S-box must permute {0,..,7}; a transcription error breaks it.
        let mut seen = [false; 8];
        for v in 0u128..8 {
            let (a, bb, c) = ((v >> 2) & 1, (v >> 1) & 1, v & 1);
            let (na, nb, nc) = sbox3_ref(a, bb, c);
            let out = ((na << 2) | (nb << 1) | nc) as usize;
            assert!(!seen[out], "sbox3_ref not a bijection at {v}");
            seen[out] = true;
        }
    }

    #[test]
    fn lowmc_matches_reference() {
        let cases: [u128; 5] = [
            0,
            1,
            u128::MAX,
            0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF,
            0xDEAD_BEEF_CAFE_F00D_1234_5678_9ABC_DEF0,
        ];
        // The commit cadence must not change the computed function — check that
        // both an every-round and an every-other-round circuit match the oracle.
        for commit_every in [1usize, 2] {
            let b = CircuitBuilder::new();
            let input: [Wire; N] = array::from_fn(|_| b.add_inout());
            let expected: [Wire; N] = array::from_fn(|_| b.add_inout());
            let out = lowmc_permutation(&b, input, commit_every);
            for j in 0..N {
                b.assert_eq("lowmc", out[j], expected[j]);
            }
            let circuit = b.build();

            for &p in &cases {
                let exp = lowmc_perm_ref(p);
                let mut w = circuit.new_witness_filler();
                for j in 0..N {
                    w[input[j]] = mask(p, j);
                    w[expected[j]] = mask(exp, j);
                }
                circuit.populate_wire_witness(&mut w).unwrap_or_else(|e| {
                    panic!("populate lowmc(ce={commit_every}, {p:#034x}): {e:?}")
                });
                verify_constraints(circuit.constraint_system(), &w.into_value_vec())
                    .unwrap_or_else(|e| {
                        panic!("constraints lowmc(ce={commit_every}, {p:#034x}): {e:?}")
                    });
            }
        }
    }

    /// Reports the binius64 AND-constraint cost of one LowMC permutation and
    /// one LowMC `tccr`, against the fixed-key-AES `tccr` baseline of
    /// 54,096 (DESIGN.md §7). Run with `--nocapture`.
    #[test]
    fn lowmc_cost() {
        const AES_TCCR: usize = 54_096;

        let perm_cost = |commit_every: usize| {
            let b = CircuitBuilder::new();
            let input: [Wire; N] = array::from_fn(|_| b.add_inout());
            let expected: [Wire; N] = array::from_fn(|_| b.add_inout());
            let out = lowmc_permutation(&b, input, commit_every);
            for j in 0..N {
                b.assert_eq("p", out[j], expected[j]);
            }
            CircuitStat::collect(&b.build()).n_and_constraints
        };
        let tccr_cost = |commit_every: usize| {
            let b = CircuitBuilder::new();
            let tweak: [Wire; N] = array::from_fn(|_| b.add_inout());
            let x: [Wire; N] = array::from_fn(|_| b.add_inout());
            let expected: [Wire; N] = array::from_fn(|_| b.add_inout());
            let out = lowmc_tccr(&b, tweak, x, commit_every);
            for j in 0..N {
                b.assert_eq("t", out[j], expected[j]);
            }
            CircuitStat::collect(&b.build()).n_and_constraints
        };

        println!("\n[lowmc-cost] params n={N}, m={M}, r={R} (Picnic-L1)");
        println!("[lowmc-cost] AES fixed-key tccr baseline = {AES_TCCR} AND-constraints");
        println!("[lowmc-cost] (each circuit includes 128 output-equality asserts)\n");
        println!("[lowmc-cost]  commit_every |  perm ANDs |  tccr ANDs |  win vs AES tccr");
        for ce in [1usize, 2] {
            let (perm, tccr) = (perm_cost(ce), tccr_cost(ce));
            println!(
                "[lowmc-cost]       {ce}       |   {perm:>6}   |   {tccr:>6}   |   {:.1}x",
                AES_TCCR as f64 / tccr as f64
            );
        }
        // The S-box ANDs (3·m·r per permutation) are the only *fundamental* cost;
        // the rest is materializing the dense linear layers (a frontend-inliner
        // limitation, not a constraint-system one). This floor is reached if the
        // linear maps are absorbed into the S-box band operands.
        let floor_tccr = 2 * 3 * M * R;
        println!(
            "\n[lowmc-cost] S-box-only floor: tccr ~= {floor_tccr} ANDs => {:.0}x (linear layers absorbed)\n",
            AES_TCCR as f64 / floor_tccr as f64
        );
    }

    /// Empirically pins binius64's per-operation AND-constraint cost, so the
    /// cost model behind the numbers above is documented rather than guessed.
    /// Each probe wraps one op in an `assert_eq`, whose own cost is the
    /// baseline.
    #[test]
    fn op_cost_probes() {
        let probe = |build: &dyn Fn(&CircuitBuilder)| {
            let b = CircuitBuilder::new();
            build(&b);
            CircuitStat::collect(&b.build()).n_and_constraints
        };
        let assert_only = probe(&|b| {
            let (x, y) = (b.add_inout(), b.add_inout());
            b.assert_eq("k", x, y);
        });
        let band_vv = probe(&|b| {
            let (x, y) = (b.add_inout(), b.add_inout());
            let o = b.band(x, y);
            b.assert_eq("k", o, x);
        });
        let band_vc = probe(&|b| {
            let x = b.add_inout();
            let c = b.add_constant_64(0xFF);
            let o = b.band(x, c);
            b.assert_eq("k", o, x);
        });
        let xor = probe(&|b| {
            let (x, y) = (b.add_inout(), b.add_inout());
            let o = b.bxor(x, y);
            b.assert_eq("k", o, x);
        });
        let shl = probe(&|b| {
            let x = b.add_inout();
            let o = b.shl(x, 1);
            b.assert_eq("k", o, x);
        });
        let sar = probe(&|b| {
            let x = b.add_inout();
            let o = b.sar(x, 63);
            b.assert_eq("k", o, x);
        });

        println!("\n[op-cost] AND-constraints per op (incl. one assert_eq each):");
        println!("[op-cost]   assert_eq alone   = {assert_only}");
        println!("[op-cost]   band(var, var)    = {band_vv}");
        println!("[op-cost]   band(var, const)  = {band_vc}");
        println!("[op-cost]   bxor(var, var)    = {xor}");
        println!("[op-cost]   shl(var, 1)       = {shl}");
        println!("[op-cost]   sar(var, 63)      = {sar}\n");
    }
}
