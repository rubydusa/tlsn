use std::time::Duration;

use anyhow::Result;
use serio::stream::IoStreamExt;
use tlsn_common::{context::build_mt_context, mux::attach_mux, Role};
use futures::{AsyncRead, AsyncWrite};
use tlsn_core::presentation::Presentation;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

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

    let presentation: Presentation = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;
    println!("Presentation: {:?}", presentation);

    Ok(())
}