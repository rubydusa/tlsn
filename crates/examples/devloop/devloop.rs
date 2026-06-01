//! Single-command dev loop: starts the TLS server in-process, then runs a
//! prover and verifier against it over an in-memory channel, and prints
//! PASS/FAIL. Intended as a fast feedback loop while hacking on the protocol
//! (including the `mpz` submodule).
//!
//! Run it with:
//!
//! ```sh
//! cargo run --example devloop
//! ```
//!
//! For a much faster loop that swaps the real MPC engine for an ideal (insecure)
//! VM — useful when iterating on protocol/plumbing rather than the MPC/garbling
//! itself — add the `tlsn_insecure` cfg:
//!
//! ```sh
//! RUSTFLAGS="--cfg tlsn_insecure" cargo run --example devloop
//! ```
//!
//! NOTE: `tlsn_insecure` replaces the garbled-circuit VM with `mpz_ideal_vm`, so
//! it does NOT exercise changes to the mpz garbling/OT layer. Use the default
//! (real MPC) run to validate those.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! Customize the experiment by editing the `CONFIG` block and the three clearly
//! marked sections below (SERVER REQUEST, SELECTIVE DISCLOSURE, VERIFIER CHECKS).
//! To change the server's responses/routes, edit
//! `crates/server-fixture/server/src/lib.rs` (it is a plain axum router).
//! ─────────────────────────────────────────────────────────────────────────

use std::{future::IntoFuture, net::SocketAddr, time::Instant};

use anyhow::{Context, Result};
use http_body_util::Empty;
use hyper::{Request, StatusCode, Uri, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpListener};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt,
};

use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::ServerName,
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

// ───────────────────────────── CONFIG (edit me) ─────────────────────────────

// The endpoint the prover requests from the in-process server fixture.
// Available routes: `/`, `/bytes?size=N`, `/formats/json`, `/formats/html`.
const ENDPOINT: &str = "/formats/json";

// Provisioned transcript size (bytes). The MPC commitment is preprocessed up
// front against these limits, so smaller = faster loop. Bump them if the
// request/response grows.
const MAX_SENT_DATA: usize = 1 << 10;
const MAX_RECV_DATA: usize = 1 << 11;

// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let start = Instant::now();
    match run().await {
        Ok(transcript) => {
            println!("\n\x1b[32m✅ PASS\x1b[0m in {:.2}s", start.elapsed().as_secs_f64());
            println!("── verified sent ──\n{}", render(transcript.sent_unsafe()));
            println!("── verified received ──\n{}", render(transcript.received_unsafe()));
        }
        Err(e) => {
            eprintln!("\n\x1b[31m❌ FAIL\x1b[0m in {:.2}s: {e:#}", start.elapsed().as_secs_f64());
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<PartialTranscript> {
    // Start the TLS HTTP server fixture in-process on an ephemeral port.
    let server_addr = spawn_server().await.context("failed to start server")?;
    let uri = format!("https://{SERVER_DOMAIN}:{}{ENDPOINT}", server_addr.port());

    // Connect prover and verifier over an in-memory channel.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, server_addr, uri);
    let verifier = verifier(verifier_socket);

    let (_, transcript) = tokio::try_join!(prover, verifier)?;
    Ok(transcript)
}

/// Binds the server fixture to an ephemeral localhost port and serves
/// connections in the background. Returns the address to dial.
async fn spawn_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    tokio::spawn(tlsn_server_fixture::bind(socket.compat_write()));
                }
                Err(e) => {
                    eprintln!("server accept error: {e}");
                    break;
                }
            }
        }
    });
    Ok(addr)
}

async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: SocketAddr,
    uri: String,
) -> Result<()> {
    let uri = uri.parse::<Uri>()?;
    let server_domain = uri.authority().unwrap().host().to_string();

    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Set up the prover and run the MPC-TLS commitment preprocessing.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;

    // Open the TLS connection to the server through the prover.
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    // ───────────────────────── SERVER REQUEST (edit me) ─────────────────────
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = request_sender.send_request(request).await?;
    anyhow::ensure!(response.status() == StatusCode::OK, "unexpected status {}", response.status());
    // ─────────────────────────────────────────────────────────────────────────

    let mut prover = prover_task.await??;

    // ──────────────────── SELECTIVE DISCLOSURE (edit me) ────────────────────
    // Default: reveal the server identity and the full transcript. To redact a
    // range, reveal `0..start` and `end..len` instead of the whole range.
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_sent(&(0..sent_len))?;
    builder.reveal_recv(&(0..recv_len))?;
    let config = builder.build()?;
    // ─────────────────────────────────────────────────────────────────────────

    prover.prove(&config).await?;
    prover.close().await?;

    handle.close();
    driver_task.await??;
    Ok(())
}

async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    // Accept the proposed MPC commitment configuration (guard against an
    // over-large request here in a real verifier).
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            let cfg = verifier.config();
            if cfg.max_sent_data() > MAX_SENT_DATA || cfg.max_recv_data() > MAX_RECV_DATA {
                verifier.reject(Some("requested transcript too large")).await?;
                anyhow::bail!("verifier rejected oversized commitment config");
            }
            verifier.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting MPC-TLS")).await?;
            anyhow::bail!("prover requested proxy mode; this loop expects MPC");
        }
    };

    let verifier = verifier.verify().await?;

    // ───────────────────────── VERIFIER CHECKS (edit me) ────────────────────
    if !verifier.request().server_identity() {
        let verifier = verifier.reject(Some("expecting the server name")).await?;
        verifier.close().await?;
        anyhow::bail!("prover did not reveal the server name");
    }
    // ─────────────────────────────────────────────────────────────────────────

    let (VerifierOutput { server_name, transcript, .. }, verifier) = verifier.accept().await?;
    verifier.close().await?;

    handle.close();
    driver_task.await??;

    let server_name = server_name.context("prover did not reveal server name")?;
    let transcript = transcript.context("prover did not reveal transcript")?;

    let ServerName::Dns(server_name) = server_name;
    anyhow::ensure!(
        server_name.as_str() == SERVER_DOMAIN,
        "server name mismatch: {} != {SERVER_DOMAIN}",
        server_name.as_str()
    );

    Ok(transcript)
}

/// Renders a partial transcript, showing redacted (unrevealed) bytes as `🙈`.
fn render(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\0', "🙈")
}
