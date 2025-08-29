use std::{env, net::{IpAddr, SocketAddr}, time::Duration};
use anyhow::Result;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serio::SinkExt;
use tlsn_core::{hash::HashAlgId, transcript::{Direction, TranscriptCommitConfig, TranscriptCommitConfigBuilder, TranscriptCommitmentKind, TranscriptSecret}, ProveConfig};
use tlsn_common::config::ProtocolConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tlsn_prover::{state::Committed, Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use spansy::{json::{JsonValue}};
use rangeset::{RangeSet, UnionMut};
use tlsn_examples::bb_service::{load_circuit_definition, BbServiceClient, CompiledCircuit, InputMap};

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const MPC_CONNECTION_ADDRESS: &str = "127.0.0.1:6142";
const BB_SERVICE_ENDPOINT: &str = "http://localhost:3000";
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

    // reveal the non-values in the json response
    builder.reveal_recv(&range_set).unwrap();

    // hash the entire response
    // TODO: compute range interactively based on the json response?
    let mut commitment_builder = TranscriptCommitConfig::builder(prover.transcript());
    commitment_builder.commit_with_kind(
        &(0..prover.transcript().received().len()), 
        Direction::Received, 
        TranscriptCommitmentKind::Hash { alg: HashAlgId::SHA256 }
    ).unwrap();
    let transcript_commit = commitment_builder.build().unwrap();
    builder.transcript_commit(transcript_commit);
    let config = builder.build().unwrap();

    // get the blinder
    let prover_output = prover.prove(&config).await.unwrap();
    let TranscriptSecret::Hash(hash_secret) = &prover_output.transcript_secrets[0] else {
        panic!("first transcript secret is not a hash");
    };
    let blinder = &hash_secret.blinder;

    let needle = b"Computer Science";
    println!("------------------Input for Noir circuit------------------");
    println!("blinder: {:?}", blinder.as_bytes());
    println!("input: {:?}", prover.transcript().received());
    println!("input length: {}", prover.transcript().received().len());
    println!("needle: {:?}", needle);
    println!("needle length: {}", needle.len());
    println!("----------------------------------------------------------");
    let transcript_data = prover.transcript().received().to_owned();
    let (mux_ctrl, mut mux_fut, mut ctx) = prover.get_connection().await.unwrap();

    // Load circuit definition from JSON file, using environment variables to get the path to the examples directory
    let examples_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR env var not set");
    let circuit_path = format!("{}/tlsn-noir-poc/target/zktlsAttestation.json", examples_dir);
    let circuit = load_circuit_definition(&circuit_path).await?;
    
    // intentionally change the blinder to test the circuit
    // let mut blinder = blinder.as_bytes().to_vec();
    // blinder[0] = 1;

    // Prepare input for the circuit
    let input_map = prepare_circuit_input(blinder.as_bytes(), &transcript_data, needle)?;
    
    // Generate proof using bb-service
    let proof_data = generate_proof_with_bb_service(circuit, input_map).await?;
    
    // Save proof to disk
    // save_proof_to_disk(&proof_data, "proof_output.json").await?;
    // println!("✅ Proof generated and saved to proof_output.json");

    mux_fut.poll_with(ctx.io_mut().send(proof_data)).await?;

    // Wait for the verifier to correctly close the connection.
    if !mux_fut.is_complete() {
        mux_ctrl.close();
        mux_fut.await?;
    }
    Ok(())
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

fn prepare_circuit_input(blinder: &[u8], transcript_data: &[u8], needle: &[u8]) -> Result<InputMap> {
    let mut input_map = InputMap::new();
    
    // Prepare input_and_blinder: combine transcript data with blinder
    let mut input_and_blinder = Vec::new();
    input_and_blinder.extend_from_slice(transcript_data);
    input_and_blinder.extend_from_slice(blinder);
    
    // Pad or truncate to expected size (1040 bytes based on the circuit ABI)
    input_and_blinder.resize(1040, 0u8);
    
    // Prepare needle array (128 bytes based on the circuit ABI)
    let mut needle_array = vec![0u8; 128];
    let copy_len = std::cmp::min(needle.len(), needle_array.len());
    needle_array[..copy_len].copy_from_slice(&needle[..copy_len]);
    
    // Convert to JSON arrays
    let input_and_blinder_json: Vec<serde_json::Value> = input_and_blinder
        .into_iter()
        .map(|byte| serde_json::Value::Number(serde_json::Number::from(byte)))
        .collect();
        
    let needle_json: Vec<serde_json::Value> = needle_array
        .into_iter()
        .map(|byte| serde_json::Value::Number(serde_json::Number::from(byte)))
        .collect();
    
    input_map.insert("input_and_blinder".to_string(), serde_json::Value::Array(input_and_blinder_json));
    input_map.insert("needle".to_string(), serde_json::Value::Array(needle_json));
    input_map.insert("input_length".to_string(), serde_json::Value::Number(serde_json::Number::from(transcript_data.len() as u32)));
    input_map.insert("needle_length".to_string(), serde_json::Value::Number(serde_json::Number::from(needle.len() as u32)));
    
    Ok(input_map)
}

async fn generate_proof_with_bb_service(circuit: CompiledCircuit, input: InputMap) -> Result<tlsn_examples::bb_service::ProofData> {
    let client = BbServiceClient::new(BB_SERVICE_ENDPOINT.to_string());
    
    // Check if bb-service is available
    if !client.health_check().await.unwrap_or(false) {
        return Err(anyhow::anyhow!("bb-service is not available at http://127.0.0.1:3000. Please start the service."));
    }
    
    println!("📡 Generating proof using bb-service...");
    let proof_data = client.generate_proof(circuit, input).await
        .map_err(|e| anyhow::anyhow!("Failed to generate proof: {}", e))?;
        
    println!("✅ Proof generated successfully!");
    Ok(proof_data)
}

// async fn save_proof_to_disk(proof_data: &tlsn_examples::bb_service::ProofData, filename: &str) -> Result<()> {
//     let proof_json = serde_json::to_string_pretty(proof_data)
//         .map_err(|e| anyhow::anyhow!("Failed to serialize proof data: {}", e))?;

//     // Print the full path where the proof will be saved, relative to the current working directory
//     let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
//     let full_path = cwd.join(filename);
//     println!("Saving proof to: {}", full_path.display());
    
//     fs::write(filename, proof_json)
//         .map_err(|e| anyhow::anyhow!("Failed to write proof to file {}: {}", filename, e))?;
        
//     println!("💾 Proof saved to {}", filename);
//     Ok(())
// }