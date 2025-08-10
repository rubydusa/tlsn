use anyhow::{bail, Result};
use std::sync::Arc;
use mpz_memory_core::{MemoryExt, ViewExt};
use serio::stream::IoStreamExt;
use tlsn_common::{context::build_mt_context, mux::attach_mux, Role};
use futures::{AsyncRead, AsyncWrite};
use tlsn_core::transcript::TranscriptCommitment;
use tlsn_core::{presentation::Presentation, CryptoProvider};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use mpz_zk::Verifier;
use mpz_core::Block;
use mpz_ot::kos::SenderConfig;
use mpz_ot::rcot::RCOTSender;
use mpz_vm_core::{
    CallableExt,
    Execute,
    memory::{
        correlated::Delta,
        binary::U8,
        Array, Vector,
    },
    Call,
};
use serio::sink::SinkExt;
use tlsn_examples::izk_common::{self, ProofRequest, dummy_circuit};

const ADDRESS: &str = "127.0.0.1:6142";

fn create_izk_verifier() -> Verifier<mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>> {
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

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting verifier on {ADDRESS}…");
    let listener = TcpListener::bind(ADDRESS).await?;
    println!("✅ Verifier listening, waiting for prover connection...");
    
    let (stream, _) = listener.accept().await?;
    println!("✅ Prover connected.");
    
    verifier_task(stream.compat()).await?;

    Ok(())
}

async fn verifier_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(socket: S) -> Result<()> {
    let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Verifier);
    let mut mt = build_mt_context(mux_ctrl.clone());
    let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

    let presentation: Presentation = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;
    // println!("Presentation: {:?}", presentation);

    let presentation_output = presentation.verify(&CryptoProvider::default())?;

    let Some(transcript_proof) = presentation_output.transcript else {
        bail!("No transcript proof found");
    };

    let target_transcript_commitment_index = presentation_output.attestation.body.transcript_commitments()
        .enumerate()
        .find(|(_, x)| matches!(x, TranscriptCommitment::Hash(_)))
        .map(|(i, _)| i)
        .expect("No hash transcript commitment found");

    let inputs_len = transcript_proof.len_received();
    let circuit = dummy_circuit(inputs_len).unwrap();
    let proof_request = ProofRequest {
        target_transcript_commitment: target_transcript_commitment_index,
        circuit: circuit.clone(),
    };
    let circuit = Arc::new(circuit);

    mux_fut.poll_with(ctx.io_mut().send(proof_request)).await?;
    let mut verifier = create_izk_verifier();
    let inputs_mem: Vector<U8> = verifier.alloc_vec(inputs_len).unwrap();
    let circuit_result_mem: Array<U8, 1> = verifier
        .call(
            Call::builder(Arc::clone(&circuit))
                .arg(inputs_mem)
                .build()
                .unwrap(),
        )
        .unwrap();

    verifier.mark_blind(inputs_mem).unwrap();
    let mut circuit_result_fut = verifier.decode(circuit_result_mem).unwrap();
    let mut hash_fut = izk_common::hash(&mut verifier, None, inputs_mem)?;

    mux_fut
        .poll_with(verifier.execute_all(&mut ctx))
        .await
        .unwrap();

    let circuit_result = circuit_result_fut.try_recv().unwrap().unwrap();
    let hash_result = hash_fut.try_recv().unwrap().unwrap();

    println!("Circuit result: {:?}", circuit_result);
    println!("Hash result: {:?}", hash_result);

    Ok(())
}