## Interactive Noir ZK Proof Example: Privacy-Preserving String Search

This example demonstrates how to use TLSNotary with Noir zero-knowledge proofs to prove that specific content exists within TLS-encrypted data without revealing the full dataset. It performs a privacy-preserving search for "Computer Science" in JSON data fetched from a test server, while keeping the sensitive parts of the response hidden.

### Running the Example

This example requires three components running simultaneously:

1. **Start the test server** (from the repository root):
```shell
RUST_LOG=info PORT=4000 cargo run --bin tlsn-server-fixture
```

2. **Start the BB service** (from the examples directory):
```shell
git submodule update --init --recursive
cd bb-service
docker compose build
docker compose up
```

3. **Run the prover** (in any order):
```shell
SERVER_PORT=4000 cargo run --release --example interactive-prove
```

4. **Run the verifier** (in any order):
```shell
cargo run --release --example interactive-verify
```

### Expected Output

**Prover Output:**
```
Starting prover on 127.0.0.1:6142…
✅ found verifier.
HTTP/1.1 200 OK
content-type: application/json
content-length: 722
connection: close
date: Mon, 01 Sep 2025 17:27:56 GMT

{"id":1234567890,"information":{"address":{"city":"Anytown","postalCode":"12345","state":"XY","street":"123 Elm Street"},"description":"John is a software engineer. He enjoys hiking, playing video games, and reading books. His favorite book is 'Moby Dick'.","education":{"degree":"Bachelor's in Computer Science","school":"Anytown University"},"family":{"parents":{"father":{"age":55,"name":"James Doe"},"mother":{"age":53,"name":"Jenny Doe"}},"siblings":[{"age":24,"name":"Jane Doe","relation":"Sister"},{"age":20,"name":"Jack Doe","relation":"Brother"}]},"favoriteColors":["blue","red","green","yellow"],"name":"John Doe"},"meta":{"createdAt":"2022-01-15T14:52:55Z","lastUpdatedAt":"2023-01-12T16:42:10Z","version":1.2}}
📡 Generating proof using bb-service...
✅ Proof generated successfully!
```

**Verifier Output:**
```
Starting verifier on 127.0.0.1:6142…
✅ Verifier listening, waiting for prover connection...
✅ Prover connected.
transcript commitments: [Hash(PlaintextHash { direction: Received, idx: Idx(RangeSet { ranges: [0..850] }), hash: TypedHash { alg: HashAlgId(1), value: Hash { value: [182, 9, 156, 160, 188, 90, 155, 140, 84, 153, 2, 150, 53, 144, 104, 120, 72, 135, 207, 252, 167, 215, 105, 52, 173, 215, 162, 158, 40, 112, 164, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 32 } } })]
🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈{"id":🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈,"information":{"address":{"city":"🙈🙈🙈🙈🙈🙈🙈","postalCode":"🙈🙈🙈🙈🙈","state":"🙈🙈","street":"🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈"},"description":"🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈","education":{"degree":"🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈","school":"🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈"},"family":{"parents":{"father":{"age":🙈🙈,"name":"🙈🙈🙈🙈🙈🙈🙈🙈🙈"},"mother":{"age":🙈🙈,"name":"🙈🙈🙈🙈🙈🙈🙈🙈🙈"}},"siblings":[{"age":🙈🙈,"name":"🙈🙈🙈🙈🙈🙈🙈🙈","relation":"🙈🙈🙈🙈🙈🙈"}🙈{"age":🙈🙈,"name":"🙈🙈🙈🙈🙈🙈🙈🙈","relation":"🙈🙈🙈🙈🙈🙈🙈"}]},"favoriteColors":[🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈],"name":"🙈🙈🙈🙈🙈🙈🙈🙈"},"meta":{"createdAt":"🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈","lastUpdatedAt":"🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈🙈","version":🙈🙈🙈}}
Received proof data
Hash in proof: [182, 9, 156, 160, 188, 90, 155, 140, 84, 153, 2, 150, 53, 144, 104, 120, 72, 135, 207, 252, 167, 215, 105, 52, 173, 215, 162, 158, 40, 112, 164, 202]
Verifying proof...
Proof verification result: true
```