use anyhow::Result;
use tlsn_core::VerifyConfig;
use tlsn_examples::bb_service::{load_circuit_definition, BbServiceClient};
use tlsn_verifier::state::Committed;
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::compat::{TokioAsyncReadCompatExt};
use tlsn_common::config::ProtocolConfigValidator;
use serio::stream::IoStreamExt;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const MPC_CONNECTION_ADDRESS: &str = "127.0.0.1:6142";
const BB_SERVICE_ENDPOINT: &str = "http://localhost:3000";

// #[derive(Parser, Debug)]
// #[command(version, about, long_about = None)]
// struct Args {
// }

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting verifier on {MPC_CONNECTION_ADDRESS}…");
    let listener = TcpListener::bind(MPC_CONNECTION_ADDRESS).await?;
    println!("✅ Verifier listening, waiting for prover connection...");
    
    let (stream, _) = listener.accept().await?;
    println!("✅ Prover connected.");
    let mut verifier = verifier_task(stream).await?;

    let verifier_output = verifier.verify(&VerifyConfig::default()).await?;

    println!("transcript commitments: {:?}", verifier_output.transcript_commitments);

    let result = bytes_to_redacted_string(verifier_output.transcript.unwrap().received_unsafe());
    println!("{}", result);

    // Get connection handles and wait to receive noir proof
    let (_mux_ctrl, mut mux_fut, mut ctx) = verifier.get_connection().await?;
    let proof_data: tlsn_examples::bb_service::ProofData = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;

    println!("Received proof data");
    // Load circuit definition from JSON file, using environment variables to get the path to the examples directory
    let examples_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR env var not set");
    let circuit_path = format!("{}/tlsn-noir-poc/target/zktlsAttestation.json", examples_dir);
    let circuit = load_circuit_definition(&circuit_path).await?;

    println!("Verifying proof...");
    let result = BbServiceClient::new(BB_SERVICE_ENDPOINT.to_string()).verify_proof(circuit, proof_data).await?;
    println!("Proof verification result: {:?}", result);

    Ok(())
}

async fn verifier_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: S, 
) -> Result<Verifier<Committed>> {
    // Set up Verifier.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let crypto_provider = tlsn_examples::interactive_noir_common::crypto_provider();
    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(crypto_provider)
        .build()
        .unwrap();
    // let verifier = Verifier::new(verifier_config);
    Ok(Verifier::new(verifier_config).setup(socket.compat()).await?.run().await?)
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}