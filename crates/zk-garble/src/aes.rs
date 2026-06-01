//! AES-128 fixed-key gadget for Binius64, built bottom-up to match mpz's
//! garbling hash (`mpz_core::aes`): `π` = fixed-key AES-128, and
//! `tccr(t, x) = π(π(x) ⊕ t) ⊕ π(x)` (eprint 2019/074 §7.4) — the hash evaluated
//! four times per garbled AND gate.
//!
//! Binius64 ships no AES gadget, so `π` is built here from its word-level ops
//! (`band`/`bxor`/`shl`/`shr`/`sar`/`bor`). Layers, each tested against
//! `mpz_core` as ground truth (DESIGN.md §9):
//!
//! 1. `gf_mul` — GF(2⁸) multiply (S-box / MixColumns core).
//! 2. `sbox` — GF inverse (`x²⁵⁴`) + AES affine map.
//! 3. `sub_bytes` / `shift_rows` / `mix_columns` / `add_round_key`.
//! 4. `aes128_fixed_key` — the 10-round permutation `π`.
//! 5. `tccr` — the garbling hash.
//!
//! State is 16 wires, byte `i` in the low 8 bits of wire `i`, in the same byte
//! order the `aes` crate / `mpz_core` use (column-major: `s[r][c]` at `r + 4c`).

use binius_frontend::{CircuitBuilder, Hint, Wire};
use mpz_core::aes::FIXED_KEY;
use std::array;

// ───────────────────────────── GF(2⁸) arithmetic ─────────────────────────────

/// GF(2⁸) multiplication modulo the AES polynomial `x⁸+x⁴+x³+x+1` (0x11B).
/// Operands are bytes in the low 8 bits; the result occupies the low 8 bits.
///
/// Branch-free: for each bit `i` of `y`, conditionally XOR `x·xⁱ mod p`, using
/// `sar(_, 63)` to turn a selected bit into an all-ones / all-zeros mask.
pub fn gf_mul(b: &CircuitBuilder, x: Wire, y: Wire) -> Wire {
    let byte = b.add_constant_64(0xFF);
    let poly = b.add_constant_64(0x1B);
    let mut acc = b.add_constant_64(0);
    let mut xi = b.band(x, byte); // x · x⁰, restricted to a byte.

    for i in 0..8u32 {
        let bit_at_msb = b.shl(y, 63 - i);
        let mask = b.sar(bit_at_msb, 63);
        let term = b.band(xi, mask);
        acc = b.bxor(acc, term);

        if i < 7 {
            // xi := xtime(xi) = ((xi << 1) & 0xFF) ^ (0x1B if bit7(xi) set).
            let hi_at_msb = b.shl(xi, 56);
            let hi_mask = b.sar(hi_at_msb, 63);
            let reduce = b.band(poly, hi_mask);
            let shifted = b.band(b.shl(xi, 1), byte);
            xi = b.bxor(shifted, reduce);
        }
    }
    b.band(acc, byte)
}

/// Out-of-circuit GF(2⁸) inverse, supplied as non-deterministic advice and
/// *verified* in-circuit (see [`gf_inv`]) rather than computed.
struct GfInvHint;

impl Hint for GfInvHint {
    const NAME: &'static str = "tlsn.gf256_inverse";

    fn shape(&self, _dimensions: &[usize]) -> (usize, usize) {
        (1, 1) // (x) -> (x⁻¹)
    }

    fn execute(&self, _dimensions: &[usize], inputs: &[binius_core::Word], outputs: &mut [binius_core::Word]) {
        let x = inputs[0].as_u64() as u8;
        outputs[0] = binius_core::Word::from_u64(inv_ref(x) as u64);
    }
}

/// GF(2⁸) inverse (with `0 ↦ 0`). The prover supplies `x⁻¹` as a hint, and the
/// circuit *verifies* it with three GF-muls instead of the 13 that a direct
/// `x²⁵⁴` exponentiation costs.
///
/// Soundness: with `p = x ⊗ inv`, the constraints `x ⊗ p == x` and
/// `inv ⊗ p == inv` pin `inv = x⁻¹` for `x ≠ 0` (then `p = 1`) and `inv = 0`
/// for `x = 0`, so a cheating prover cannot supply a wrong inverse.
fn gf_inv(b: &CircuitBuilder, x: Wire) -> Wire {
    let byte = b.add_constant_64(0xFF);
    let x = b.band(x, byte);
    let inv = b.band(b.call_hint(GfInvHint, &[], &[x])[0], byte);
    let p = gf_mul(b, x, inv);
    b.assert_eq("gf_inv: x·(x·inv) = x", gf_mul(b, x, p), x);
    b.assert_eq("gf_inv: inv·(x·inv) = inv", gf_mul(b, inv, p), inv);
    inv
}

/// 8-bit left rotation of a byte held in the low 8 bits.
fn rotl8(b: &CircuitBuilder, x: Wire, n: u32) -> Wire {
    let byte = b.add_constant_64(0xFF);
    let lo = b.shl(x, n);
    let hi = b.shr(x, 8 - n);
    b.band(b.bor(lo, hi), byte)
}

/// AES S-box: `affine(inv(x))`, with the affine map expressed as
/// `y ⊕ (y⋘1) ⊕ (y⋘2) ⊕ (y⋘3) ⊕ (y⋘4) ⊕ 0x63` (8-bit rotations).
pub fn sbox(b: &CircuitBuilder, x: Wire) -> Wire {
    let y = gf_inv(b, x);
    let c = b.add_constant_64(0x63);
    let byte = b.add_constant_64(0xFF);
    let s = b.bxor_multi(&[y, rotl8(b, y, 1), rotl8(b, y, 2), rotl8(b, y, 3), rotl8(b, y, 4), c]);
    b.band(s, byte)
}

// ───────────────────────────── AES state layers ──────────────────────────────

fn add_round_key(b: &CircuitBuilder, state: [Wire; 16], rk: [u8; 16]) -> [Wire; 16] {
    array::from_fn(|i| {
        let k = b.add_constant_64(rk[i] as u64);
        b.bxor(state[i], k)
    })
}

fn sub_bytes(b: &CircuitBuilder, state: [Wire; 16]) -> [Wire; 16] {
    array::from_fn(|i| sbox(b, state[i]))
}

/// ShiftRows as a byte permutation on the column-major state.
const SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

fn shift_rows(state: [Wire; 16]) -> [Wire; 16] {
    array::from_fn(|i| state[SHIFT_ROWS[i]])
}

/// MixColumns: each column `(a0,a1,a2,a3)` mapped via the AES matrix, using
/// `3·a = 2·a ⊕ a`.
fn mix_columns(b: &CircuitBuilder, state: [Wire; 16]) -> [Wire; 16] {
    let two = b.add_constant_64(2);
    let mut out = state;
    for c in 0..4 {
        let i = 4 * c;
        let a = [state[i], state[i + 1], state[i + 2], state[i + 3]];
        let m = [gf_mul(b, a[0], two), gf_mul(b, a[1], two), gf_mul(b, a[2], two), gf_mul(b, a[3], two)];
        out[i] = b.bxor_multi(&[m[0], m[1], a[1], a[2], a[3]]); // 2a0 ⊕ 3a1 ⊕ a2 ⊕ a3
        out[i + 1] = b.bxor_multi(&[a[0], m[1], m[2], a[2], a[3]]); // a0 ⊕ 2a1 ⊕ 3a2 ⊕ a3
        out[i + 2] = b.bxor_multi(&[a[0], a[1], m[2], m[3], a[3]]); // a0 ⊕ a1 ⊕ 2a2 ⊕ 3a3
        out[i + 3] = b.bxor_multi(&[m[0], a[0], a[1], a[2], m[3]]); // 3a0 ⊕ a1 ⊕ a2 ⊕ 2a3
    }
    out
}

/// Fixed-key AES-128 permutation `π` (the round keys for `FIXED_KEY` are
/// precomputed as build-time constants).
pub fn aes128_fixed_key(b: &CircuitBuilder, input: [Wire; 16]) -> [Wire; 16] {
    let rk = key_expansion(FIXED_KEY);
    let mut state = add_round_key(b, input, rk[0]);
    for round in rk.iter().take(10).skip(1) {
        state = sub_bytes(b, state);
        state = shift_rows(state);
        state = mix_columns(b, state);
        state = add_round_key(b, state, *round);
    }
    state = sub_bytes(b, state);
    state = shift_rows(state);
    add_round_key(b, state, rk[10])
}

/// The garbling hash `tccr(t, x) = π(π(x) ⊕ t) ⊕ π(x)`.
pub fn tccr(b: &CircuitBuilder, tweak: [Wire; 16], x: [Wire; 16]) -> [Wire; 16] {
    let px = aes128_fixed_key(b, x);
    let p_xor_t: [Wire; 16] = array::from_fn(|i| b.bxor(px[i], tweak[i]));
    let ppt = aes128_fixed_key(b, p_xor_t);
    array::from_fn(|i| b.bxor(ppt[i], px[i]))
}

// ─── Reference AES helpers (build-time: round-key schedule; also test oracles) ───

fn xtime_ref(a: u8) -> u8 {
    let h = a & 0x80;
    let r = a << 1;
    if h != 0 { r ^ 0x1B } else { r }
}

fn gf_mul_ref(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn inv_ref(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }
    let mut r = 1u8;
    for _ in 0..254 {
        r = gf_mul_ref(r, x);
    }
    r
}

fn affine_ref(b: u8) -> u8 {
    let mut y = 0u8;
    for i in 0..8 {
        let bit = ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1);
        y |= bit << i;
    }
    y ^ 0x63
}

fn sbox_ref(x: u8) -> u8 {
    affine_ref(inv_ref(x))
}

/// AES-128 key schedule: 11 round keys (16 bytes each), column-major byte order.
fn key_expansion(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 4]; 44];
    for (i, word) in w.iter_mut().take(4).enumerate() {
        *word = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    let mut rcon = 1u8;
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]]; // RotWord
            for t in temp.iter_mut() {
                *t = sbox_ref(*t); // SubWord
            }
            temp[0] ^= rcon;
            rcon = xtime_ref(rcon);
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }
    let mut rks = [[0u8; 16]; 11];
    for r in 0..11 {
        for c in 0..4 {
            for j in 0..4 {
                rks[r][4 * c + j] = w[4 * r + c][j];
            }
        }
    }
    rks
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::{verify::verify_constraints, word::Word};
    use mpz_core::{
        aes::{AesEncryptor, FixedKeyAes},
        Block,
    };

    /// Runs `block` through the circuit and checks the constraints hold, given
    /// the input wires/expected wires already declared.
    fn check(circuit: &binius_frontend::Circuit, ins: &[(Wire, u8)], label: &str) {
        let mut w = circuit.new_witness_filler();
        for &(wire, val) in ins {
            w[wire] = Word(val as u64);
        }
        circuit
            .populate_wire_witness(&mut w)
            .unwrap_or_else(|e| panic!("populate {label}: {e:?}"));
        verify_constraints(circuit.constraint_system(), &w.into_value_vec())
            .unwrap_or_else(|e| panic!("constraints {label}: {e:?}"));
    }

    #[test]
    fn sbox_matches_reference() {
        // Anchor the reference against known AES S-box values, and confirm it is
        // a bijection (a transcription/logic error almost surely breaks this).
        assert_eq!(sbox_ref(0x00), 0x63);
        assert_eq!(sbox_ref(0x01), 0x7c);
        let mut seen = [false; 256];
        for x in 0..256 {
            let s = sbox_ref(x as u8) as usize;
            assert!(!seen[s], "sbox_ref not a bijection at {x:#04x}");
            seen[s] = true;
        }

        let builder = CircuitBuilder::new();
        let x = builder.add_inout();
        let expected = builder.add_inout();
        let out = sbox(&builder, x);
        builder.assert_eq("sbox", out, expected);
        let circuit = builder.build();

        for v in 0u16..256 {
            check(&circuit, &[(x, v as u8), (expected, sbox_ref(v as u8))], &format!("sbox({v:#04x})"));
        }
    }

    #[test]
    fn aes128_matches_mpz() {
        // Round key 0 must equal the key.
        assert_eq!(key_expansion(FIXED_KEY)[0], FIXED_KEY);

        let builder = CircuitBuilder::new();
        let input: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let expected: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let out = aes128_fixed_key(&builder, input);
        for i in 0..16 {
            builder.assert_eq("aes", out[i], expected[i]);
        }
        let circuit = builder.build();

        let cipher = AesEncryptor::new(Block::new(FIXED_KEY));
        let blocks: [[u8; 16]; 4] = [
            [0u8; 16],
            [0xFFu8; 16],
            array::from_fn(|i| i as u8),
            array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
        ];
        for blk in blocks {
            let exp = cipher.encrypt_block(Block::new(blk)).to_bytes();
            let ins: Vec<(Wire, u8)> = (0..16)
                .map(|i| (input[i], blk[i]))
                .chain((0..16).map(|i| (expected[i], exp[i])))
                .collect();
            check(&circuit, &ins, "aes128");
        }
    }

    #[test]
    fn tccr_matches_mpz() {
        let builder = CircuitBuilder::new();
        let tweak: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let x: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let expected: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let out = tccr(&builder, tweak, x);
        for i in 0..16 {
            builder.assert_eq("tccr", out[i], expected[i]);
        }
        let circuit = builder.build();

        let h = FixedKeyAes::new(FIXED_KEY);
        let cases: [([u8; 16], [u8; 16]); 3] = [
            ([0u8; 16], [0u8; 16]),
            (1u128.to_le_bytes(), array::from_fn(|i| i as u8)),
            (array::from_fn(|i| (i as u8).wrapping_mul(7)), [0xABu8; 16]),
        ];
        for (t, xb) in cases {
            let exp = h.tccr(Block::new(t), Block::new(xb)).to_bytes();
            let ins: Vec<(Wire, u8)> = (0..16)
                .map(|i| (tweak[i], t[i]))
                .chain((0..16).map(|i| (x[i], xb[i])))
                .chain((0..16).map(|i| (expected[i], exp[i])))
                .collect();
            check(&circuit, &ins, "tccr");
        }
    }

    // Reports the binius64 constraint count for one `tccr` evaluation — the
    // number that decides whether proving a whole garbling is tractable. Run
    // with `--nocapture`. A garbled AND gate hashes 4 values, so its
    // proof-of-garbling cost is ~4x this; a circuit with `and_count` AND gates
    // costs ~`4 * and_count` of these.
    #[test]
    fn tccr_cost() {
        use binius_frontend::CircuitStat;
        let builder = CircuitBuilder::new();
        let tweak: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let x: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let expected: [Wire; 16] = array::from_fn(|_| builder.add_inout());
        let out = tccr(&builder, tweak, x);
        for i in 0..16 {
            builder.assert_eq("tccr", out[i], expected[i]);
        }
        let circuit = builder.build();
        let s = CircuitStat::collect(&circuit);
        println!(
            "\n[cost] one tccr(): gates={}, AND-constraints={}, MUL-constraints={}",
            s.n_gates, s.n_and_constraints, s.n_mul_constraints
        );
        println!(
            "[cost] per garbled AND gate (4x tccr) ~= {} AND-constraints\n",
            4 * s.n_and_constraints
        );
    }
}
