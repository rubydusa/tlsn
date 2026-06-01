//! AES-128 fixed-key gadget for Binius64, built bottom-up to match mpz's
//! garbling hash (`mpz_core::aes`): `π` = fixed-key AES-128, and
//! `tccr(t, x) = π(π(x) ⊕ t) ⊕ π(x)` (eprint 2019/074 §7.4), the hash evaluated
//! four times per garbled AND gate.
//!
//! Binius64 ships no AES gadget, so we build `π` from its word-level ops
//! (`band`/`bxor`/`shl`/`shr`/`sar`). This is **milestone 1** (DESIGN.md §9):
//! the GF(2⁸) multiply that is the arithmetic core of the S-box and MixColumns.
//! Remaining layers — S-box (inverse + affine), ShiftRows, MixColumns,
//! AddRoundKey with the precomputed `FIXED_KEY` schedule, the 10-round
//! permutation, and the TCCR wrapper — are TODO.

use binius_frontend::{CircuitBuilder, Wire};

/// GF(2⁸) multiplication modulo the AES/Rijndael polynomial
/// `x⁸ + x⁴ + x³ + x + 1` (0x11B). Operands are bytes held in the low 8 bits of
/// a 64-bit word; the result occupies the low 8 bits.
///
/// Branch-free: for each bit `i` of `y`, conditionally XOR `x·xⁱ mod p` into the
/// accumulator. The "conditional" is realized by moving bit `i` to the MSB and
/// arithmetic-shifting right by 63 (`sar`), which yields an all-ones mask when
/// the bit is set and all-zeros otherwise.
pub fn gf_mul(b: &CircuitBuilder, x: Wire, y: Wire) -> Wire {
    let byte = b.add_constant_64(0xFF);
    let poly = b.add_constant_64(0x1B);
    let mut acc = b.add_constant_64(0);
    let mut xi = b.band(x, byte); // x · x⁰, restricted to a byte.

    for i in 0..8u32 {
        // mask = 0xFF..FF if bit i of y is set, else 0.
        let bit_at_msb = b.shl(y, 63 - i);
        let mask = b.sar(bit_at_msb, 63);
        let term = b.band(xi, mask);
        acc = b.bxor(acc, term);

        if i < 7 {
            // xi := xtime(xi) = ((xi << 1) & 0xFF) ^ (0x1B if bit7(xi) set).
            let hi_at_msb = b.shl(xi, 56); // bit 7 -> MSB.
            let hi_mask = b.sar(hi_at_msb, 63);
            let reduce = b.band(poly, hi_mask);
            let shifted = b.band(b.shl(xi, 1), byte);
            xi = b.bxor(shifted, reduce);
        }
    }
    b.band(acc, byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::{verify::verify_constraints, word::Word};

    /// Reference GF(2⁸) multiply (AES field) to cross-check the gadget.
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

    #[test]
    fn gf_mul_matches_reference() {
        // Sanity-check the reference against the canonical AES spec vector.
        assert_eq!(gf_mul_ref(0x57, 0x83), 0xC1);

        // Build the circuit once: out = gf_mul(x, y), asserted equal to a public
        // `expected`. A correct gadget satisfies the constraint for every case.
        let builder = CircuitBuilder::new();
        let x = builder.add_inout();
        let y = builder.add_inout();
        let expected = builder.add_inout();
        let out = gf_mul(&builder, x, y);
        builder.assert_eq("gf_mul", out, expected);
        let circuit = builder.build();

        // Cover every `a` against the S-box/MixColumns-relevant multipliers, plus
        // a few explicit edge vectors.
        let mut cases: Vec<(u8, u8)> =
            vec![(0x57, 0x83), (0x00, 0xFF), (0x01, 0x01), (0xFF, 0xFF), (0x53, 0xCA)];
        for a in 0u16..256 {
            for &c in &[0x01u8, 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e] {
                cases.push((a as u8, c));
            }
        }

        for (a, c) in cases {
            let mut w = circuit.new_witness_filler();
            w[x] = Word(a as u64);
            w[y] = Word(c as u64);
            w[expected] = Word(gf_mul_ref(a, c) as u64);
            circuit
                .populate_wire_witness(&mut w)
                .unwrap_or_else(|e| panic!("populate gf_mul({a:#04x}, {c:#04x}): {e:?}"));
            verify_constraints(circuit.constraint_system(), &w.into_value_vec())
                .unwrap_or_else(|e| panic!("gf_mul({a:#04x}, {c:#04x}) wrong: {e:?}"));
        }
    }
}
