## Interactive Noir ZK Proof Example: Privacy-Preserving String Search

This example demonstrates how to use TLSNotary with Noir zero-knowledge proofs to prove that specific content exists within TLS-encrypted data without revealing the full dataset. It performs a privacy-preserving search for "Computer Science" in JSON data fetched from a test server, while keeping the sensitive parts of the response hidden.

### Running the Example

This example requires three components running simultaneously:

1. **Start the test server** (from the repository root):
```shell
RUST_LOG=info PORT=4000 cargo run --bin tlsn-server-fixture
```

2. **Run the prover** (in any order):
```shell
SERVER_PORT=4000 cargo run --release --example interactive-prove
```

3. **Run the verifier** (in any order):
```shell
SERVER_PORT=4000 cargo run --release --example interactive-verify
```

### Expected Output

**Prover Output:**
```
Starting prover on 127.0.0.1:6142&
✅ found verifier.
[Full HTTP response with JSON data]
------------------Input for Noir circuit------------------
blinder: [217, 193, 176, 86, 235, 104, 85, 251, ...]
input: [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, ...]
input length: 850
needle: [67, 111, 109, 112, 117, 116, 101, 114, 32, 83, 99, 105, 101, 110, 99, 101]
needle length: 16
----------------------------------------------------------
```

**Verifier Output:**
```
Starting verifier on 127.0.0.1:6142&
✅ Verifier listening, waiting for prover connection...
✅ Prover connected.
transcript commitments: [Hash(PlaintextHash { ... })]
[JSON response with sensitive values redacted as 🙈 symbols]
```