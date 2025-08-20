use std::{env, net::{IpAddr, SocketAddr}, time::Duration};
use anyhow::Result;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tlsn_core::ProveConfig;
use tlsn_common::config::ProtocolConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tlsn_prover::{state::Committed, Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use spansy::{json::{JsonValue}};
use rangeset::{RangeSet, UnionMut};

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const MPC_CONNECTION_ADDRESS: &str = "127.0.0.1:6142";
const DEFAULT_FIXTURE_PORT: u16 = 4000;

// #[derive(Parser, Debug)]
// #[command(version, about, long_about = None)]
// struct Args {
// }

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting prover on {MPC_CONNECTION_ADDRESS}…");

    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // We use SERVER_DOMAIN here to make sure it matches the domain in the test
    // server's certificate.
    let uri = format!("https://{SERVER_DOMAIN}:{server_port}/formats/json");
    let server_ip: IpAddr = server_host.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::from((server_ip, server_port));

    let stream = loop {
        match TcpStream::connect(MPC_CONNECTION_ADDRESS).await {
            Ok(s) => break s,
            Err(e) if e.kind() == tokio::io::ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("✅ found verifier.");
    prover_task(stream, server_addr, &uri).await?;

    Ok(())
}

async fn prover_task<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: S, 
    server_addr: SocketAddr,
    uri: &str,
) -> Result<()> {
    // get server domain
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();

    let mut prover = mpc_tls_prover(socket, server_domain, server_addr, uri.clone()).await?;
    let mut builder = ProveConfig::builder(prover.transcript());
    // Reveal the DNS name.
    builder.server_identity();

    let response = spansy::http::parse_response(prover.transcript().received()).unwrap();
    let body_content = response.body.as_ref().map(|b| &b.content).unwrap();
    let range_set = match body_content {
        spansy::http::BodyContent::Json(obj) => {
            json_non_content_range_set(obj)
        }
        _ => panic!("non json-object body")
    };

    // print the full received data
    println!("{}", String::from_utf8_lossy(prover.transcript().received()));

    builder.reveal_recv(&range_set).unwrap();
    let config = builder.build().unwrap();
    prover.prove(&config).await.unwrap();
    Ok(prover.close().await.unwrap())
}

async fn mpc_tls_prover<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: S,
    server_domain: &str,
    server_addr: SocketAddr,
    uri: Uri,
) -> Result<Prover<Committed>> {
    let crypto_provider = tlsn_examples::interactive_noir_common::crypto_provider();
    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(server_domain)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()
                .unwrap(),
        )
        .crypto_provider(crypto_provider);

    let prover_config = prover_config_builder.build().unwrap();
    let prover = Prover::new(prover_config)
        .setup(socket.compat())
        .await
        .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();
    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);
    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();
    // Spawn the connection to run in the background.
    tokio::spawn(connection);
    // MPC-TLS: Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri)
        .header("Host", server_domain)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();
    assert!(response.status() == StatusCode::OK);
    // Create proof for the Verifier.
    Ok(prover_task.await.unwrap().unwrap())
}

fn json_non_content_range_set(json: &JsonValue) -> RangeSet<usize> {
    let mut range_set = RangeSet::new(&[]);
    let mut stack = vec![json];
    while let Some(item) = stack.pop() {
        match item {
            JsonValue::Object(obj) => {
                range_set.union_mut(&obj.without_pairs());
                stack.extend(obj.elems.iter().map(|kv| {
                    range_set.union_mut(&kv.without_value());
                    &kv.value
                }));
            }
            JsonValue::Array(arr) => {
                range_set.union_mut(&arr.without_values());
                stack.extend(arr.elems.iter());
            }
            _ => {}
        }
    }
    range_set
}