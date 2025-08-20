use std::sync::Arc;

use anyhow::{anyhow, Result};
use mpz_common::Context;
use mpz_core::Block;
use mpz_memory_core::correlated::Delta;
use mpz_ot::kos::{ReceiverConfig, SenderConfig};
use mpz_ot::rcot::{RCOTReceiver, RCOTSender};
use serde::{Deserialize, Serialize};
use mpz_circuits::{Circuit, CircuitBuilder};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{binary::{Binary, U8}, DecodeFutureTyped, MemoryExt, Vector, ViewExt};
use mpz_vm_core::{Call, CallableExt, Vm};
use tls_server_fixture::CA_CERT_DER;
use tlsn_core::{hash::Blinder, CryptoProvider};
use tls_core::verify::WebPkiVerifier;
use mpz_zk::{Prover, Verifier};

pub enum RoleArgs {
    Prover(ProverRoleArgs),
    Verifier(VerifierRoleArgs),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequest {
    pub target_transcript_commitment: usize,
    pub circuit: Circuit,
}

pub struct ProofResult {
    pub circuit_output: Vec<u8>,
    pub hash_output: Vec<u8>
}

pub struct ProverRoleArgs {
    pub inputs: Vec<u8>,
    pub blinder: Blinder,
}

pub struct VerifierRoleArgs;

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
pub fn apply_sha256(
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

// assumptions: inputs and outputs sizes of circuit are bytes (multiples of 8)
pub async fn perform_proof(
    ctx: &mut Context, 
    circuit: Circuit,
    role_args: RoleArgs,
) -> Result<ProofResult> {
    let mut vm: Box<dyn Vm<Binary> + Send> = match &role_args {
        RoleArgs::Prover(ProverRoleArgs { .. }) => Box::new(create_izk_prover()),
        RoleArgs::Verifier(VerifierRoleArgs) => Box::new(create_izk_verifier()),
    };

    // TODO: for now the entire input of the hash is the input to the general purpose circuit
    let inputs_mem: Vector<U8> = vm.alloc_vec(circuit.inputs().len() / 8)?;
    let circuit_result_mem: Vector<U8> = vm
        .call(
            Call::builder(Arc::new(circuit))
                .arg(inputs_mem)
                .build()?,
        )?;
    let blinder = match role_args {
        RoleArgs::Prover(ProverRoleArgs { inputs, blinder }) => {
            vm.mark_private(inputs_mem)?;
            vm.assign(inputs_mem, inputs)?;
            vm.commit(inputs_mem)?;
            Some(blinder)
        },
        RoleArgs::Verifier(VerifierRoleArgs) => {
            vm.mark_blind(inputs_mem)?;
            vm.commit(inputs_mem)?;
            None
        }
    };

    if let Some(blinder) = &blinder {
        println!("blinder: {:?}", blinder.as_bytes());
    }

    let mut circuit_result_fut = vm.decode(circuit_result_mem)?;
    let mut hash_fut = apply_sha256(
        vm.as_mut(), 
        blinder, 
        inputs_mem
    )?;

    vm.execute_all(ctx).await?;

    Ok(ProofResult {
        circuit_output: circuit_result_fut.try_recv()?.ok_or_else(|| anyhow!("no circuit output"))?,
        hash_output: hash_fut.try_recv()?.ok_or_else(|| anyhow!("no hash output"))?,
    })
}

fn create_izk_prover() -> Prover<mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>> {
    let mut receiver = mpz_ot::kos::Receiver::new(
        ReceiverConfig::default(),
        mpz_ot::chou_orlandi::Sender::new(),
    );
    // I don't know why but without manually allocating, it will underallocate OTs and panic
    receiver.alloc(128).unwrap();
    Prover::new(receiver)
}

fn create_izk_verifier() -> Verifier<mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>> {
    // note: in production should be random
    let delta = Block::new([255; 16]);
    let mut sender = mpz_ot::kos::Sender::new(
        SenderConfig::default(),
        delta,
        mpz_ot::chou_orlandi::Receiver::new(),
    );
    // I don't know why but without manually allocating, it will underallocate OTs and panic
    sender.alloc(128).unwrap();
    Verifier::new(Delta::new(delta), sender)
}
