//! Binary-field multiply cost probe — the step-2 decision gate (HASH_CODESIGN.md
//! §milestones, item 1).
//!
//! binius64's frontend exposes no native GF(2ᵏ) multiply — only bitwise
//! AND/XOR/shift and 64-bit *integer* MUL. An algebraic garbling hash such as
//! Vision is dominated by GF(2³²)/GF(2¹²⁸) multiplies and inversions, each of
//! which must therefore be built from word ops. This module measures that unit
//! cost so we can decide whether Vision-in-binius64 can beat the 54,096-AND
//! fixed-key-AES `tccr` baseline, or whether the word machine instead favors a
//! low-AND-count primitive.

use binius_frontend::{CircuitBuilder, Wire};

/// GF(2³²) multiply modulo `x³² + x⁷ + x³ + x² + 1` (reduction constant 0x8D).
/// Operands in the low 32 bits; result in the low 32 bits. Same shift-and-reduce
/// structure as the GF(2⁸) `aes::gf_mul`, widened to 32 bits (Vision Mark-32's
/// field).
pub fn gf32_mul(b: &CircuitBuilder, x: Wire, y: Wire) -> Wire {
    let mask = b.add_constant_64(0xFFFF_FFFF);
    let poly = b.add_constant_64(0x8D);
    let mut acc = b.add_constant_64(0);
    let mut xi = b.band(x, mask);
    for i in 0..32u32 {
        let bit_at_msb = b.shl(y, 63 - i);
        let sel = b.sar(bit_at_msb, 63);
        acc = b.bxor(acc, b.band(xi, sel));
        if i < 31 {
            let hi_at_msb = b.shl(xi, 32); // bit 31 -> MSB
            let hi = b.sar(hi_at_msb, 63);
            let reduce = b.band(poly, hi);
            xi = b.bxor(b.band(b.shl(xi, 1), mask), reduce);
        }
    }
    b.band(acc, mask)
}

/// GF(2⁶⁴) multiply modulo `x⁶⁴ + x⁴ + x³ + x + 1` (reduction constant 0x1B) —
/// the field whose elements are exactly one binius64 word (the "wouldn't 2⁶⁴
/// match perfectly?" case). Reduce-as-you-go keeps `xi` in-field; the result is
/// the full word.
pub fn gf64_mul(b: &CircuitBuilder, x: Wire, y: Wire) -> Wire {
    let poly = b.add_constant_64(0x1B);
    let mut acc = b.add_constant_64(0);
    let mut xi = x;
    for i in 0..64u32 {
        let sel = b.sar(b.shl(y, 63 - i), 63);
        acc = b.bxor(acc, b.band(xi, sel));
        if i < 63 {
            let hi = b.sar(xi, 63); // bit 63 (MSB) -> mask
            let reduce = b.band(poly, hi);
            xi = b.bxor(b.shl(xi, 1), reduce);
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::gf_mul;
    use binius_core::{verify::verify_constraints, word::Word};
    use binius_frontend::CircuitStat;

    fn gf32_mul_ref(mut a: u32, mut b: u32) -> u32 {
        let mut p = 0u32;
        for _ in 0..32 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x8000_0000;
            a <<= 1;
            if hi != 0 {
                a ^= 0x8D;
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn gf32_mul_matches_reference() {
        let builder = CircuitBuilder::new();
        let x = builder.add_inout();
        let y = builder.add_inout();
        let expected = builder.add_inout();
        let out = gf32_mul(&builder, x, y);
        builder.assert_eq("gf32", out, expected);
        let circuit = builder.build();

        let vals = [0u32, 1, 2, 0xFF, 0x1_0000, 0xFFFF_FFFF, 0x1234_5678, 0xDEAD_BEEF];
        for &a in &vals {
            for &c in &vals {
                let mut w = circuit.new_witness_filler();
                w[x] = Word(a as u64);
                w[y] = Word(c as u64);
                w[expected] = Word(gf32_mul_ref(a, c) as u64);
                circuit.populate_wire_witness(&mut w).unwrap();
                verify_constraints(circuit.constraint_system(), &w.into_value_vec())
                    .unwrap_or_else(|e| panic!("gf32_mul({a:#x},{c:#x}): {e:?}"));
            }
        }
        // Algebraic anchors.
        assert_eq!(gf32_mul_ref(0xABCD_1234, 1), 0xABCD_1234);
        assert_eq!(gf32_mul_ref(12345, 67890), gf32_mul_ref(67890, 12345));
    }

    fn gf64_mul_ref(mut a: u64, mut b: u64) -> u64 {
        let mut p = 0u64;
        for _ in 0..64 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x8000_0000_0000_0000;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn gf64_mul_matches_reference() {
        let builder = CircuitBuilder::new();
        let x = builder.add_inout();
        let y = builder.add_inout();
        let expected = builder.add_inout();
        let out = gf64_mul(&builder, x, y);
        builder.assert_eq("gf64", out, expected);
        let circuit = builder.build();
        let vals = [0u64, 1, 2, 0xFF, 0xDEAD_BEEF_CAFE_F00D, u64::MAX, 0x1234_5678_9ABC_DEF0];
        for &a in &vals {
            for &c in &vals {
                let mut w = circuit.new_witness_filler();
                w[x] = Word(a);
                w[y] = Word(c);
                w[expected] = Word(gf64_mul_ref(a, c));
                circuit.populate_wire_witness(&mut w).unwrap();
                verify_constraints(circuit.constraint_system(), &w.into_value_vec())
                    .unwrap_or_else(|e| panic!("gf64_mul({a:#x},{c:#x}): {e:?}"));
            }
        }
    }

    /// Per-multiply AND-constraint cost in binius64's word frontend across field
    /// sizes — including GF(2⁶⁴), which fits one word exactly. Run `--nocapture`.
    #[test]
    fn binary_field_mul_cost() {
        let cost = |build: &dyn Fn(&CircuitBuilder)| {
            let b = CircuitBuilder::new();
            build(&b);
            CircuitStat::collect(&b.build()).n_and_constraints
        };
        let gf8 = cost(&|b| {
            let (x, y) = (b.add_inout(), b.add_inout());
            let o = gf_mul(b, x, y);
            b.assert_eq("k", o, x);
        });
        let gf32 = cost(&|b| {
            let (x, y) = (b.add_inout(), b.add_inout());
            let o = gf32_mul(b, x, y);
            b.assert_eq("k", o, x);
        });
        let gf64 = cost(&|b| {
            let (x, y) = (b.add_inout(), b.add_inout());
            let o = gf64_mul(b, x, y);
            b.assert_eq("k", o, x);
        });

        println!("\n[bf-cost] one variable GF(2^k) multiply, built from word ops:");
        println!("[bf-cost]   GF(2^8)  = {gf8} AND-constraints");
        println!("[bf-cost]   GF(2^32) = {gf32} AND-constraints");
        println!("[bf-cost]   GF(2^64) = {gf64} AND-constraints  (= 1 word, the 'perfect match')");
        println!("[bf-cost] vs a *native* field-mul constraint in original Binius: ~1.\n");
    }
}
