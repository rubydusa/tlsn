use anyhow::Result;
use tlsn_core::VerifyConfig;
use tlsn_examples::bb_service::{load_circuit_definition, BbServiceClient, ProofData};
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

    let hash = get_hash_from_proof(&proof_data).expect("Failed to get hash from proof");
    println!("Hash in proof: {:?}", hash);

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

fn get_hash_from_proof(proof_data: &ProofData) -> Result<Vec<u8>, ()> {
    let public_inputs = parse_public_inputs(&proof_data.public_inputs).expect("Failed to parse public inputs");
    let a = &public_inputs[130..162];
    // Take every member of `a`, skip "0x" if present, take first byte, concat everything
    let mut bytes = Vec::new();
    for hex_str in a {
        // If hex_str starts with "0x", skip first two chars
        let hex = if hex_str.starts_with("0x") {
            &hex_str[2..]
        } else {
            &hex_str[..]
        };
        if hex.len() >= 2 {
            if let Some(last_two) = hex.get(hex.len().saturating_sub(2)..) {
                if let Ok(byte) = u8::from_str_radix(last_two, 16) {
                    bytes.push(byte);
                }
            }
        }
    }
    Ok(bytes)
}

// ai slop parse function
/// Parse public inputs binary buffer into an array of hex strings
/// Each field element is 32 bytes (256 bits)
const FIELD_BYTE_SIZE: usize = 32;
fn parse_public_inputs(buffer: &[u8]) -> Result<Vec<String>, ()> {
    if buffer.len() % FIELD_BYTE_SIZE != 0 {
        return Err(());
    }

    let num_inputs = buffer.len() / FIELD_BYTE_SIZE;
    let mut public_inputs = Vec::with_capacity(num_inputs);

    for i in 0..num_inputs {
        let start = i * FIELD_BYTE_SIZE;
        let end = start + FIELD_BYTE_SIZE;
        let chunk = &buffer[start..end];
        
        // Convert chunk to hex string with 0x prefix
        let hex_string = format!("0x{}", hex::encode(chunk));
        public_inputs.push(hex_string);
    }

    Ok(public_inputs)
}