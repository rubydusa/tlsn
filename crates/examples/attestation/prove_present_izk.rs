use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tlsn_core::presentation::Presentation;
use tlsn_common::{context::build_mt_context, mux::attach_mux, Role};
use futures::{AsyncRead, AsyncWrite};
use serio::sink::SinkExt;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

const ADDRESS: &str = "127.0.0.1:6142";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the saved presentation file
    #[arg(short, long, default_value = "example-json.presentation.tlsn")]
    file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let presentation_data = fs::read(&args.file)?;
    let presentation: Presentation = bincode::deserialize(&presentation_data)?;

    println!("Successfully loaded presentation from: {:?}", args.file);
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
    prover_task(stream.compat(), presentation).await?;

    Ok(())
}

async fn prover_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(socket: S, presentation: Presentation) -> Result<()> {
    let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Prover);
    let mut mt = build_mt_context(mux_ctrl.clone());
    let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

    mux_fut.poll_with(ctx.io_mut().send(presentation)).await?;
    mux_fut.poll_with(tokio::time::sleep(std::time::Duration::from_millis(1000))).await;

    Ok(())
}