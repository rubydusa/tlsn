use anyhow::{bail, Context, Result};
use serio::stream::IoStreamExt;
use tlsn_common::{context::build_mt_context, mux::attach_mux, Role};
use futures::{AsyncRead, AsyncWrite};
use tlsn_core::{
    presentation::Presentation,
    transcript::TranscriptCommitment,
};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use serio::sink::SinkExt;
use tlsn_examples::izk_common::{self, dummy_circuit, perform_proof, ProofRequest, RoleArgs, VerifierRoleArgs};

const ADDRESS: &str = "127.0.0.1:6142";


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

    // get the presentation and verify it
    let crypto_provider = izk_common::permissive_crypto_provider();
    let presentation: Presentation = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;
    let presentation_output = presentation.verify(&crypto_provider)?;

    let Some(transcript_proof) = presentation_output.transcript else {
        bail!("No transcript proof found");
    };

    // target the first hash transcript commitment (assuming there's only one and it's SHA256)
    let (target_transcript_commitment_index, original_hash) = presentation_output.attestation.body.transcript_commitments()
        .enumerate()
        .find_map(|(i, x)| match x {
            TranscriptCommitment::Hash(x) => Some((i, x)),
            _ => None
        })
        .context("no hash transcript commitment found")?;

    let inputs_len = transcript_proof.len_received();
    let circuit = dummy_circuit(inputs_len).unwrap();
    let proof_request = ProofRequest {
        target_transcript_commitment: target_transcript_commitment_index,
        circuit: circuit.clone(),
    };
    mux_fut.poll_with(ctx.io_mut().send(proof_request)).await?;

    let result = mux_fut.poll_with(perform_proof(&mut ctx, circuit, RoleArgs::Verifier(VerifierRoleArgs))).await?;

    println!("Circuit output: {:?}", result.circuit_output);
    println!("Original hash: {:?}", original_hash);
    println!("Hash output: {:?}", result.hash_output);

    mux_ctrl.close();

    Ok(())
}