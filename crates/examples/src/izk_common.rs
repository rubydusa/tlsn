use anyhow::Result;
use serde::{Deserialize, Serialize};
use mpz_circuits::{circuits::xor, Circuit, CircuitBuilder};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{binary::{Binary, U8}, DecodeFutureTyped, MemoryExt, Vector, ViewExt};
use mpz_vm_core::Vm;
use tlsn_core::hash::Blinder;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequest {
    pub target_transcript_commitment: usize,
    pub circuit: Circuit,
}

// take arbitrary number of inputs, and return a circuit that returns the xor of the first two bits
pub fn dummy_circuit(inputs: usize) -> Result<Circuit> {
    let mut builder = CircuitBuilder::new();
    let input_nodes = (0..inputs).map(|_| builder.add_input()).collect::<Vec<_>>();

    let xor_node = builder.add_xor_gate(input_nodes[0], input_nodes[1]);

    // repeat 8 times so that the output is a byte
    (0..8).for_each(|_| builder.add_output(xor_node));

    Ok(builder.build()?)
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
