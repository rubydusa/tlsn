use std::{fs, iter::zip};
use std::path::PathBuf;
use std::time::Duration;
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Parser;
use mpz_memory_core::{MemoryExt, ViewExt};
use mpz_vm_core::CallableExt;
use tlsn_core::transcript::TranscriptSecret;
use tlsn_core::{hash::{HashAlgId, TypedHash}, presentation::Presentation, transcript::{hash::PlaintextHash, Direction, TranscriptCommitment}, CryptoProvider, Secrets};
use tlsn_common::{context::build_mt_context, mux::attach_mux, Role};
use futures::{AsyncRead, AsyncWrite};
use serio::sink::SinkExt;
use serio::stream::IoStreamExt;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tlsn_examples::izk_common::{self, dummy_circuit, ProofRequest};
use mpz_zk::Prover;
use mpz_ot::rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput};
use mpz_ot::{
    self,
    kos::{ReceiverConfig, SenderConfig},
};
use mpz_vm_core::{
    Execute,
    memory::{
        binary::U8,
        Array, Vector,
    },
    Call,
};


const ADDRESS: &str = "127.0.0.1:6142";

fn create_izk_prover() -> Prover<mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>> {
    let mut receiver = mpz_ot::kos::Receiver::new(
        ReceiverConfig::default(),
        mpz_ot::chou_orlandi::Sender::new(),
    );
    // I don't know why but without manually allocating, it will underallocate OTs and panic
    receiver.alloc(128).unwrap();
    Prover::new(receiver)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the saved presentation file
    #[arg(short, long, default_value = "example-json.presentation.tlsn")]
    presentation_file: PathBuf,
    /// Path to the saved secrets file
    #[arg(short, long, default_value = "example-json.secrets.tlsn")]
    secrets_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let presentation_data = fs::read(&args.presentation_file)?;
    let secrets_data = fs::read(&args.secrets_file)?;
    let presentation: Presentation = bincode::deserialize(&presentation_data)?;
    let secrets: Secrets = bincode::deserialize(&secrets_data)?;

    println!("Successfully loaded presentation from: {:?}", args.presentation_file);
    println!("Successfully loaded secrets from: {:?}", args.secrets_file);
    println!("Connecting to {ADDRESS}…");
    let stream = loop {
        match TcpStream::connect(ADDRESS).await {
            Ok(s) => break s,
            Err(e) if e.kind() == tokio::io::ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("✅ found verifier.");
    prover_task(stream.compat(), presentation, secrets).await?;

    Ok(())
}

async fn prover_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(socket: S, presentation: Presentation, secrets: Secrets) -> Result<()> {
    let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Prover);
    let mut mt = build_mt_context(mux_ctrl.clone());
    let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

    let presentation_output = presentation.clone().verify(&CryptoProvider::default())?;

    mux_fut.poll_with(ctx.io_mut().send(presentation)).await?;
    // mux_fut.poll_with(tokio::time::sleep(std::time::Duration::from_millis(1000))).await;

    let proof_request: ProofRequest = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;
    let circuit = Arc::new(proof_request.circuit);
    
    let Some((TranscriptCommitment::Hash(
        PlaintextHash { 
            direction: Direction::Received, 
            hash: TypedHash { 
                alg: HashAlgId::SHA256, 
                value: hash }, 
                .. 
            }
        ), TranscriptSecret::Hash(commitment_secret))) = presentation_output
        .attestation.body
        .transcript_commitments()
        .zip(&secrets.transcript_commitment_secrets)
        .nth(proof_request.target_transcript_commitment) else {
        bail!("Transcript commitment not found, or not of expected form")
    };

    let original_transcript = secrets.transcript();
    // for simplicity of example, we commit to the entire received transcript
    let inputs = original_transcript.received();
    let input_len = inputs.len();

    let mut prover = create_izk_prover();
    let inputs_mem: Vector<U8> = prover.alloc_vec(input_len).unwrap();

    let circuit_result_mem: Array<U8, 1> = prover
        .call(
            Call::builder(Arc::clone(&circuit))
                .arg(inputs_mem)
                .build()
                .unwrap(),
        )
        .unwrap();

    prover.mark_private(inputs_mem).unwrap();
    prover.assign(inputs_mem, inputs.to_owned()).unwrap();

    let mut circuit_result_fut = prover.decode(circuit_result_mem).unwrap();
    let mut hash_fut = izk_common::hash(&mut prover, Some(commitment_secret.blinder.clone()), inputs_mem)?;

    mux_fut
        .poll_with(prover.execute_all(&mut ctx))
        .await
        .unwrap();

    let circuit_result = circuit_result_fut.try_recv().unwrap().unwrap();
    let hash_result = hash_fut.try_recv().unwrap().unwrap();

    println!("Circuit result: {:?}", circuit_result);
    println!("Hash result: {:?}", hash_result);

    Ok(())
}