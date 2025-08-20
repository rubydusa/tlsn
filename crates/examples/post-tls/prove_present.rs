use std::{fs, path::PathBuf, time::Duration};
use anyhow::{bail, Result};
use clap::Parser;
use tlsn_core::{hash::{HashAlgId, TypedHash, Hash}, presentation::{Presentation, PresentationOutput}, transcript::{hash::PlaintextHash, Direction, TranscriptCommitment, TranscriptSecret}, Secrets};
use tlsn_common::{context::build_mt_context, mux::attach_mux, Role};
use futures::{AsyncRead, AsyncWrite};
use serio::{sink::SinkExt, stream::IoStreamExt};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tlsn_examples::post_tls_common::{ProofRequest, ProverRoleArgs, RoleArgs, perform_proof, permissive_crypto_provider};

const ADDRESS: &str = "127.0.0.1:6142";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the saved presentation file
    #[arg(short, long, default_value = "example-json.presentation.tlsn")]
    presentation_file: PathBuf,
    /// Path to the saved secrets file
    #[arg(short, long, default_value = "example-json.secrets.tlsn")]
    secrets_file: PathBuf,
    /// Path to save the sha256 input file
    #[arg(long, default_value = "sha256_preimage.json")]
    sha256_preimage_dest: PathBuf,
}

fn prepare_proof(
    presentation_output: &PresentationOutput, 
    secrets: &Secrets,
    proof_request: &ProofRequest,
) -> Result<(ProverRoleArgs, Hash)> {
    // TODO: for now doesn't really process the direction and idx of the committment,
    // only works if it's a Direction::Received and idx is the entire transcript
    let Some((TranscriptCommitment::Hash(
        PlaintextHash { 
            direction: Direction::Received, 
            hash: TypedHash { 
                alg: HashAlgId::SHA256, 
                value: hash }, 
                idx: _idx
            }
        ), TranscriptSecret::Hash(commitment_secret))) = presentation_output
        .attestation.body
        .transcript_commitments()
        .zip(secrets.transcript_commitment_secrets.iter())
        .nth(proof_request.target_transcript_commitment) else {
        bail!("Transcript commitment not found, or not of expected form")
    };

    Ok((ProverRoleArgs {
        inputs: secrets.transcript().received().to_owned(),
        blinder: commitment_secret.blinder.clone(),
    }, hash.clone()))
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
    prover_task(stream.compat(), presentation, secrets, args).await?;

    Ok(())
}

async fn prover_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(socket: S, presentation: Presentation, secrets: Secrets, args: Args) -> Result<()> {
    // initialize the mux and context handlers
    let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Prover);
    let mut mt = build_mt_context(mux_ctrl.clone());
    let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

    // send the presentation to the verifier
    let crypto_provider = permissive_crypto_provider();
    let presentation_output = presentation.clone().verify(&crypto_provider)?;
    mux_fut.poll_with(ctx.io_mut().send(presentation)).await?;

    // receive the proof request from the verifier
    let proof_request: ProofRequest = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;
    let (role_args, hash) = prepare_proof(&presentation_output, &secrets, &proof_request)?;
    fs::write(args.sha256_preimage_dest, serde_json::to_string(&role_args.inputs)?)?;
    let circuit = proof_request.circuit;

    let result = mux_fut.poll_with(perform_proof(
        &mut ctx, 
        circuit, 
        RoleArgs::Prover(role_args)
    )).await?;

    println!("Circuit output: {:?}", result.circuit_output);
    println!("Original Hash: {:?}", hash);
    println!("Hash output: {:?}", result.hash_output);

    // wait until verifier closes the connection
    mux_fut.await?;

    Ok(())
}