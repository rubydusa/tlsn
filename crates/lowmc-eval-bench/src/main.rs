#![allow(dead_code)]
//! Microbenchmark for the ONLINE EVALUATION cost of a LowMC-as-garbling-hash
//! circuit — the one cost that runs live during the TLS session and is therefore
//! bounded by the server's read timeout (garbling and proving are offline). See
//! `../zk-garble/HASH_CODESIGN.md` for how this fits the proof-of-garbling work.
//!
//! It evaluates a clean-room bitsliced LowMC-128/128/20 permutation (the hash
//! `H`; one garbled AND gate costs 2 `tccr` = 4 permutations to evaluate) over a
//! 512-block AVX-512 batch, and reports cost in FREQUENCY-INVARIANT cycles/block
//! (the dev laptop throttles, so ns is unreliable; cycles/block is throttle-proof,
//! measured via `perf-event`).
//!
//! Backends compared (see `HASH_CODESIGN.md` for the analysis):
//! - `v1`      — compact gather, bounds-checked, autovectorized (baseline).
//! - `tight_a` — CSR index + `get_unchecked`, autovectorized. WORSE than v1: the
//!               autovectorizer mangles the inner XOR. Kept as a data point.
//! - `tight_b` — CSR + unchecked + explicit AVX-512 (`acc` pinned in a `zmm`).
//!               WINNER: ~730 cyc/block, instructions halved, ~1.6× over v1.
//! - `tight_c`/`tight_d` — 4/8 independent accumulators. Lift IPC but add
//!               instructions: cycles plateau — we are now load/throughput bound.
//!
//! NOT included: the fully-unrolled "matrix codegen" variant (bake every fixed
//! matrix into straight-line XOR trees). It is a 13× REGRESSION — the megabytes
//! of unrolled code starve the front-end (IPC 0.45); bitslicing already amortizes
//! the per-set-bit bookkeeping across 512 blocks, so a compact loop hot in L1I
//! wins. Documented in `HASH_CODESIGN.md`; omitted here (13 MB binary, ~9 min build).

use perf_event::events::Hardware;
use perf_event::Builder;
use std::arch::x86_64::*;
use std::hint::black_box;
use std::time::Instant;

const N: usize = 128;
const M: usize = 10;
const R: usize = 20;
const LANES: usize = 8;
const W: usize = LANES * 64;
const SEED: u64 = 0x1234_5678_9ABC_DEF0;

type Slice = [u64; LANES];
const ZERO: Slice = [0u64; LANES];

#[inline(always)]
fn xor(a: Slice, b: Slice) -> Slice {
    let mut o = ZERO;
    for l in 0..LANES {
        o[l] = a[l] ^ b[l];
    }
    o
}
#[inline(always)]
fn and(a: Slice, b: Slice) -> Slice {
    let mut o = ZERO;
    for l in 0..LANES {
        o[l] = a[l] & b[l];
    }
    o
}

fn splitmix64(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn gen_mats() -> Vec<[[u64; 2]; N]> {
    let mut st = SEED;
    let mut v = Vec::with_capacity(R);
    for _ in 0..R {
        let mut rows = [[0u64; 2]; N];
        for j in 0..N {
            rows[j][0] = splitmix64(&mut st);
            rows[j][1] = splitmix64(&mut st);
        }
        v.push(rows);
    }
    v
}

// Baseline: per-output index lists with bounds-checked gather.
fn gen_idx(mats: &[[[u64; 2]; N]]) -> Vec<Vec<Vec<u16>>> {
    mats.iter()
        .map(|rows| {
            (0..N)
                .map(|j| {
                    let mut idx = Vec::new();
                    for i in 0..64 {
                        if (rows[j][0] >> i) & 1 == 1 {
                            idx.push(i as u16);
                        }
                    }
                    for i in 0..64 {
                        if (rows[j][1] >> i) & 1 == 1 {
                            idx.push((64 + i) as u16);
                        }
                    }
                    idx
                })
                .collect()
        })
        .collect()
}

// Flattened CSR: all set-bit indices contiguous; `off[r*N+j .. +1]` slices output j.
struct Csr {
    flat: Vec<u16>,
    off: Vec<u32>,
}
fn build_csr(mats: &[[[u64; 2]; N]]) -> Csr {
    let mut flat = Vec::new();
    let mut off = Vec::with_capacity(R * N + 1);
    off.push(0u32);
    for rows in mats {
        for j in 0..N {
            for i in 0..64 {
                if (rows[j][0] >> i) & 1 == 1 {
                    flat.push(i as u16);
                }
            }
            for i in 0..64 {
                if (rows[j][1] >> i) & 1 == 1 {
                    flat.push((64 + i) as u16);
                }
            }
            off.push(flat.len() as u32);
        }
    }
    Csr { flat, off }
}

fn gen_rcs() -> Vec<[u64; 2]> {
    let mut st = SEED ^ 0xABCD_EF01_2345_6789;
    (0..R).map(|_| [splitmix64(&mut st), splitmix64(&mut st)]).collect()
}
fn expand_rc(rcs: &[[u64; 2]]) -> Vec<[Slice; N]> {
    rcs.iter()
        .map(|c| {
            let mut a = [ZERO; N];
            for j in 0..N {
                if (c[j >> 6] >> (j & 63)) & 1 == 1 {
                    a[j] = [u64::MAX; LANES];
                }
            }
            a
        })
        .collect()
}

#[inline(always)]
fn sbox_bs(st: &mut [Slice; N]) {
    for j in 0..M {
        let c = st[3 * j];
        let b = st[3 * j + 1];
        let a = st[3 * j + 2];
        let bc = and(b, c);
        let ac = and(a, c);
        let ab = and(a, b);
        st[3 * j + 2] = xor(a, bc);
        st[3 * j + 1] = xor(xor(a, b), ac);
        st[3 * j] = xor(xor(xor(a, b), c), ab);
    }
}

// --- linear backends ---

#[inline(never)]
fn linear_v1(idx: &[Vec<u16>], src: &[Slice; N], dst: &mut [Slice; N]) {
    for j in 0..N {
        let mut acc = ZERO;
        for &i in &idx[j] {
            let s = &src[i as usize];
            for l in 0..LANES {
                acc[l] ^= s[l];
            }
        }
        dst[j] = acc;
    }
}

// CSR + unchecked, inner XOR autovectorized over [u64; 8].
#[inline(never)]
fn linear_tight_a(csr: &Csr, r: usize, src: &[Slice; N], dst: &mut [Slice; N]) {
    unsafe {
        for j in 0..N {
            let s = *csr.off.get_unchecked(r * N + j) as usize;
            let e = *csr.off.get_unchecked(r * N + j + 1) as usize;
            let mut acc = ZERO;
            for k in s..e {
                let i = *csr.flat.get_unchecked(k) as usize;
                let sp = src.get_unchecked(i);
                for l in 0..LANES {
                    acc[l] ^= sp[l];
                }
            }
            *dst.get_unchecked_mut(j) = acc;
        }
    }
}

// CSR + unchecked, inner accumulate as explicit AVX-512 (acc pinned in zmm).
#[target_feature(enable = "avx512f")]
unsafe fn linear_tight_b(csr: &Csr, r: usize, src: &[Slice; N], dst: &mut [Slice; N]) {
    for j in 0..N {
        let s = *csr.off.get_unchecked(r * N + j) as usize;
        let e = *csr.off.get_unchecked(r * N + j + 1) as usize;
        let mut acc = _mm512_setzero_si512();
        for k in s..e {
            let i = *csr.flat.get_unchecked(k) as usize;
            let v = _mm512_loadu_si512(src.get_unchecked(i).as_ptr().cast());
            acc = _mm512_xor_si512(acc, v);
        }
        _mm512_storeu_si512(dst.get_unchecked_mut(j).as_mut_ptr().cast(), acc);
    }
}

macro_rules! ld {
    ($src:expr, $flat:expr, $k:expr) => {
        _mm512_loadu_si512($src.get_unchecked(*$flat.get_unchecked($k) as usize).as_ptr().cast())
    };
}

// 4 independent accumulators: breaks the serial XOR dependency chain for ILP.
#[target_feature(enable = "avx512f")]
unsafe fn linear_tight_c(csr: &Csr, r: usize, src: &[Slice; N], dst: &mut [Slice; N]) {
    let flat = &csr.flat;
    for j in 0..N {
        let s = *csr.off.get_unchecked(r * N + j) as usize;
        let e = *csr.off.get_unchecked(r * N + j + 1) as usize;
        let mut a0 = _mm512_setzero_si512();
        let mut a1 = _mm512_setzero_si512();
        let mut a2 = _mm512_setzero_si512();
        let mut a3 = _mm512_setzero_si512();
        let mut k = s;
        while k + 4 <= e {
            a0 = _mm512_xor_si512(a0, ld!(src, flat, k));
            a1 = _mm512_xor_si512(a1, ld!(src, flat, k + 1));
            a2 = _mm512_xor_si512(a2, ld!(src, flat, k + 2));
            a3 = _mm512_xor_si512(a3, ld!(src, flat, k + 3));
            k += 4;
        }
        while k < e {
            a0 = _mm512_xor_si512(a0, ld!(src, flat, k));
            k += 1;
        }
        let acc = _mm512_xor_si512(_mm512_xor_si512(a0, a1), _mm512_xor_si512(a2, a3));
        _mm512_storeu_si512(dst.get_unchecked_mut(j).as_mut_ptr().cast(), acc);
    }
}

// 8 independent accumulators.
#[target_feature(enable = "avx512f")]
unsafe fn linear_tight_d(csr: &Csr, r: usize, src: &[Slice; N], dst: &mut [Slice; N]) {
    let flat = &csr.flat;
    for j in 0..N {
        let s = *csr.off.get_unchecked(r * N + j) as usize;
        let e = *csr.off.get_unchecked(r * N + j + 1) as usize;
        let mut a = [_mm512_setzero_si512(); 8];
        let mut k = s;
        while k + 8 <= e {
            a[0] = _mm512_xor_si512(a[0], ld!(src, flat, k));
            a[1] = _mm512_xor_si512(a[1], ld!(src, flat, k + 1));
            a[2] = _mm512_xor_si512(a[2], ld!(src, flat, k + 2));
            a[3] = _mm512_xor_si512(a[3], ld!(src, flat, k + 3));
            a[4] = _mm512_xor_si512(a[4], ld!(src, flat, k + 4));
            a[5] = _mm512_xor_si512(a[5], ld!(src, flat, k + 5));
            a[6] = _mm512_xor_si512(a[6], ld!(src, flat, k + 6));
            a[7] = _mm512_xor_si512(a[7], ld!(src, flat, k + 7));
            k += 8;
        }
        while k < e {
            a[0] = _mm512_xor_si512(a[0], ld!(src, flat, k));
            k += 1;
        }
        let acc = _mm512_xor_si512(
            _mm512_xor_si512(_mm512_xor_si512(a[0], a[1]), _mm512_xor_si512(a[2], a[3])),
            _mm512_xor_si512(_mm512_xor_si512(a[4], a[5]), _mm512_xor_si512(a[6], a[7])),
        );
        _mm512_storeu_si512(dst.get_unchecked_mut(j).as_mut_ptr().cast(), acc);
    }
}

fn perm<L: Fn(usize, &[Slice; N], &mut [Slice; N])>(
    st0: &[Slice; N],
    rc: &[[Slice; N]],
    lin: L,
    out: &mut [Slice; N],
) {
    let mut bufs = [*st0, [ZERO; N]];
    let mut cur = 0usize;
    for round in 0..R {
        sbox_bs(&mut bufs[cur]);
        {
            let (a, b) = bufs.split_at_mut(1);
            let (src, dst) = if cur == 0 { (&a[0], &mut b[0]) } else { (&b[0], &mut a[0]) };
            lin(round, src, dst);
        }
        let d = cur ^ 1;
        for j in 0..N {
            bufs[d][j] = xor(bufs[d][j], rc[round][j]);
        }
        cur ^= 1;
    }
    *out = bufs[cur];
}

// --- scalar reference ---
fn get(x: &[u64; 2], k: usize) -> u64 {
    (x[k >> 6] >> (k & 63)) & 1
}
fn set(x: &mut [u64; 2], k: usize, v: u64) {
    let w = k >> 6;
    let m = 1u64 << (k & 63);
    x[w] = (x[w] & !m) | ((v & 1) << (k & 63));
}
fn sbox_scalar(x: &mut [u64; 2]) {
    for j in 0..M {
        let a = get(x, 3 * j + 2);
        let b = get(x, 3 * j + 1);
        let c = get(x, 3 * j);
        let na = a ^ (b & c);
        let nb = a ^ b ^ (a & c);
        let nc = a ^ b ^ c ^ (a & b);
        set(x, 3 * j + 2, na);
        set(x, 3 * j + 1, nb);
        set(x, 3 * j, nc);
    }
}
fn matvec(rows: &[[u64; 2]; N], x: &[u64; 2]) -> [u64; 2] {
    let mut out = [0u64; 2];
    for j in 0..N {
        let p = (rows[j][0] & x[0]) ^ (rows[j][1] & x[1]);
        if p.count_ones() & 1 == 1 {
            out[j >> 6] |= 1u64 << (j & 63);
        }
    }
    out
}
fn perm_scalar(mats: &[[[u64; 2]; N]], rcs: &[[u64; 2]], x0: &[u64; 2]) -> [u64; 2] {
    let mut x = *x0;
    for r in 0..R {
        sbox_scalar(&mut x);
        x = matvec(&mats[r], &x);
        x[0] ^= rcs[r][0];
        x[1] ^= rcs[r][1];
    }
    x
}

fn bench<F: FnMut()>(label: &str, iters: usize, mut f: F) -> Option<(f64, f64, f64)> {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let cyc = Builder::new().kind(Hardware::CPU_CYCLES).build();
    let ins = Builder::new().kind(Hardware::INSTRUCTIONS).build();
    let (mut cyc, mut ins) = match (cyc, ins) {
        (Ok(c), Ok(i)) => (c, i),
        _ => {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            let ns = t.elapsed().as_nanos() as f64 / (iters as f64 * W as f64);
            println!("  {label:12} (perf denied)  {ns:7.1} ns/blk");
            return None;
        }
    };
    let mut fe = Builder::new().kind(Hardware::STALLED_CYCLES_FRONTEND).build().ok();
    let mut be = Builder::new().kind(Hardware::STALLED_CYCLES_BACKEND).build().ok();
    let _ = cyc.reset();
    let _ = ins.reset();
    if let Some(c) = fe.as_mut() {
        let _ = c.reset();
        let _ = c.enable();
    }
    if let Some(c) = be.as_mut() {
        let _ = c.reset();
        let _ = c.enable();
    }
    let _ = cyc.enable();
    let _ = ins.enable();
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let el = t.elapsed();
    let _ = cyc.disable();
    let _ = ins.disable();
    if let Some(c) = fe.as_mut() {
        let _ = c.disable();
    }
    if let Some(c) = be.as_mut() {
        let _ = c.disable();
    }
    let c = cyc.read().unwrap_or(0) as f64;
    let i = ins.read().unwrap_or(0) as f64;
    let fec = fe.as_mut().and_then(|x| x.read().ok()).unwrap_or(0) as f64;
    let bec = be.as_mut().and_then(|x| x.read().ok()).unwrap_or(0) as f64;
    let blocks = iters as f64 * W as f64;
    let cpb = c / blocks;
    let ipb = i / blocks;
    let ipc = if c > 0.0 { i / c } else { 0.0 };
    let nspb = el.as_nanos() as f64 / blocks;
    let fep = if c > 0.0 { 100.0 * fec / c } else { 0.0 };
    let bep = if c > 0.0 { 100.0 * bec / c } else { 0.0 };
    println!(
        "  {label:12} {cpb:8.1} cyc/blk  {ipb:8.1} ins/blk  IPC {ipc:.2}  | FE {fep:3.0}% BE {bep:3.0}%  | {nspb:6.1} ns (noisy)"
    );
    Some((cpb, ipb, ipc))
}

fn main() {
    let mats = gen_mats();
    let idx = gen_idx(&mats);
    let csr = build_csr(&mats);
    let rcs = gen_rcs();
    let rc_bs = expand_rc(&rcs);

    let x0 = [0xDEAD_BEEF_1234_5678u64, 0x9ABC_DEF0_0F1E_2D3Cu64];
    let exp = perm_scalar(&mats, &rcs, &x0);
    let mut inp = [ZERO; N];
    for j in 0..N {
        inp[j][0] = (x0[j >> 6] >> (j & 63)) & 1;
    }
    let check = |o: &[Slice; N]| (0..N).all(|j| (o[j][0] & 1) == ((exp[j >> 6] >> (j & 63)) & 1));

    let mut o1 = [ZERO; N];
    perm(&inp, &rc_bs, |r, s, d| linear_v1(&idx[r], s, d), &mut o1);
    let mut oa = [ZERO; N];
    perm(&inp, &rc_bs, |r, s, d| linear_tight_a(&csr, r, s, d), &mut oa);
    let mut ob = [ZERO; N];
    perm(&inp, &rc_bs, |r, s, d| unsafe { linear_tight_b(&csr, r, s, d) }, &mut ob);
    let mut oc = [ZERO; N];
    perm(&inp, &rc_bs, |r, s, d| unsafe { linear_tight_c(&csr, r, s, d) }, &mut oc);
    let mut od = [ZERO; N];
    perm(&inp, &rc_bs, |r, s, d| unsafe { linear_tight_d(&csr, r, s, d) }, &mut od);

    println!("correctness v1:      {}", if check(&o1) { "PASS" } else { "FAIL" });
    println!("correctness tight_a: {}", if check(&oa) && oa == o1 { "PASS" } else { "FAIL" });
    println!("correctness tight_b: {}", if check(&ob) && ob == o1 { "PASS" } else { "FAIL" });
    println!("correctness tight_c: {}", if check(&oc) && oc == o1 { "PASS" } else { "FAIL" });
    println!("correctness tight_d: {}", if check(&od) && od == o1 { "PASS" } else { "FAIL" });

    const ITERS: usize = 4000;
    let inp_b = black_box(inp);
    let mut out = [ZERO; N];

    println!("\nLowMC eval — cyc/block FREQUENCY-INVARIANT (lower = better):");
    let v1 = bench("v1 gather", ITERS, || {
        perm(black_box(&inp_b), &rc_bs, |r, s, d| linear_v1(&idx[r], s, d), &mut out);
        black_box(&out);
    });
    let ta = bench("tight_a", ITERS, || {
        perm(black_box(&inp_b), &rc_bs, |r, s, d| linear_tight_a(&csr, r, s, d), &mut out);
        black_box(&out);
    });
    let tb = bench("tight_b 1acc", ITERS, || {
        perm(black_box(&inp_b), &rc_bs, |r, s, d| unsafe { linear_tight_b(&csr, r, s, d) }, &mut out);
        black_box(&out);
    });
    let tc = bench("tight_c 4acc", ITERS, || {
        perm(black_box(&inp_b), &rc_bs, |r, s, d| unsafe { linear_tight_c(&csr, r, s, d) }, &mut out);
        black_box(&out);
    });
    let td = bench("tight_d 8acc", ITERS, || {
        perm(black_box(&inp_b), &rc_bs, |r, s, d| unsafe { linear_tight_d(&csr, r, s, d) }, &mut out);
        black_box(&out);
    });
    let _ = ta;

    let cands = [("tight_b", tb), ("tight_c", tc), ("tight_d", td)];
    let best = cands
        .iter()
        .filter_map(|(n, o)| o.map(|(c, _, _)| (*n, c)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    if let (Some((c1, _, _)), Some((bn, cb))) = (v1, best) {
        println!("\n  best ({bn}) {cb:.1} cyc/blk vs v1 gather {c1:.1}: {:.2}x fewer", c1 / cb);
        for &gh in &[2.8e9f64, 4.0e9f64] {
            let nspp = cb / gh * 1e9;
            let sess = cb * 10.4e6 / gh;
            println!(
                "  @ {:.1} GHz: {:.0} ns/perm -> session eval (10.4M perms) ~= {:.2} s",
                gh / 1e9,
                nspp,
                sess
            );
        }
    }
}
