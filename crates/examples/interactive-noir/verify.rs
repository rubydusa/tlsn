use std::time::Duration;
use anyhow::Result;
use tlsn_core::{VerifierOutput, VerifyConfig};
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{TokioAsyncReadCompatExt};
use tlsn_common::config::ProtocolConfigValidator;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const MPC_CONNECTION_ADDRESS: &str = "127.0.0.1:6142";

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
    verifier_task(stream).await?;

    Ok(())
}

async fn verifier_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: S, 
) -> Result<VerifierOutput> {
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
    let verifier = Verifier::new(verifier_config);

    Ok(verifier
        .verify(socket.compat(), &VerifyConfig::default())
        .await
        .unwrap())
}