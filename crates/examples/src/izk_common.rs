use anyhow::Result;
use serde::{Deserialize, Serialize};
use mpz_circuits::{circuits::xor, Circuit, CircuitBuilder};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{binary::{Binary, U8}, DecodeFutureTyped, MemoryExt, Vector, ViewExt};
use mpz_vm_core::Vm;
use tls_server_fixture::CA_CERT_DER;
use tlsn_core::{hash::Blinder, CryptoProvider};
use tls_core::verify::WebPkiVerifier;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequest {
    pub target_transcript_commitment: usize,
    pub circuit: Circuit,
}

// take arbitrary number of inputs
// return 0 if b0 ^ b1 == 0
// return 255 if b0 ^ b1 == 1
pub fn dummy_circuit(input_bytes: usize) -> Result<Circuit> {
    let inputs = input_bytes * 8;
    let mut builder = CircuitBuilder::new();
    let input_nodes = (0..inputs).map(|_| builder.add_input()).collect::<Vec<_>>();

    // this code returns 62 - there is some logic that prohibits reusing nodes in a certain way I need to understand
    // ---
    // let xor_node = builder.add_xor_gate(input_nodes[0], input_nodes[1]);
    // // repeat 8 times so that the output is a byte
    // (0..8).for_each(|_| builder.add_output(xor_node));
    // ---

    (0..8)
        .for_each(|_| {
            let xor = builder.add_xor_gate(input_nodes[0], input_nodes[1]);
            let inv = builder.add_inv_gate(xor);
            builder.add_output(inv);
        });

    Ok(builder.build()?)
}

pub fn permissive_crypto_provider() -> CryptoProvider {
    // Create a crypto provider accepting the server-fixture's self-signed
    // root certificate.
    //
    // This is only required for offline testing with the server-fixture. In
    // production, use `CryptoProvider::default()` instead.
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    }
}

// if blinder is some, then it means it's the prover
// if blinder is none, then it's the verifier
pub fn hash(
    vm: &mut dyn Vm<Binary>,
    blinder: Option<Blinder>,
    target: Vector<U8>
) -> Result<DecodeFutureTyped<BitVec, Vec<u8>>> {
    let blinder_ref = vm.alloc_vec::<U8>(16)?;
    match blinder {
        Some(blinder) => {
            vm.mark_private(blinder_ref)?;
            vm.assign(blinder_ref, blinder.as_bytes().to_vec())?;
            vm.commit(blinder_ref)?;
        },
        None => {
            vm.mark_blind(blinder_ref)?;
            vm.commit(blinder_ref)?;
        },
    }

    let mut hasher = Sha256::new_with_init(vm)?;
    hasher.update(&target);
    hasher.update(&blinder_ref);
    let hash_ref = hasher.finalize(vm)?;

    let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;
    Ok(hash_fut)
}
